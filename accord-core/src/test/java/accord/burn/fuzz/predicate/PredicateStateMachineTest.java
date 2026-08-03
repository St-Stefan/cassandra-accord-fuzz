/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package accord.burn.fuzz.predicate;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import accord.burn.fuzz.trace.Trace;
import accord.burn.fuzz.trace.TraceEvent;
import accord.local.Node;
import accord.messages.MessageType.StandardMessage;
import accord.primitives.Routable.Domain;
import accord.primitives.Txn.Kind;
import accord.primitives.TxnId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PredicateStateMachineTest {

    private static final long NO_ID = Integer.MIN_VALUE;
    private static final int N = 7;

    private static Node.Id node(int i) { return new Node.Id(i); }

    private static TxnId txn(int coordinatorId, int hlc) {
        return new TxnId(1, hlc, Kind.Write, Domain.Key, node(coordinatorId));
    }

    private static TraceEvent.Deliver preAcceptReq(long eventId, Node.Id coordinator, Node.Id to, TxnId txnId, long requestId) {
        return new TraceEvent.Deliver(eventId, eventId, eventId, coordinator, to,
                StandardMessage.PRE_ACCEPT_REQ, txnId, "PreAccept", requestId, NO_ID, 0);
    }

    private static TraceEvent.Deliver preAcceptOk(long eventId, Node.Id from, Node.Id coordinator, TxnId txnId, long replyId) {
        return new TraceEvent.Deliver(eventId, eventId, eventId, from, coordinator,
                StandardMessage.PRE_ACCEPT_RSP, txnId, "PreAcceptOk", NO_ID, replyId, 0);
    }

    /**
     * A single transaction's PreAccept sent to 3 of 7 nodes, then acked by all 3, replayed as
     * growing prefixes. The visited-state set must only grow, and a full replay must match
     * feeding every event through {@link PredicateStateMachine#apply}.
     */
    @Test
    void visitedStatesGrowMonotonicallyOverIncreasingPrefixes() {
        TxnId t = txn(1, 1);
        Trace trace = new Trace(new Trace.Header(1L, N, 1, "test-1.0"));
        long e = 1;
        trace.add(preAcceptReq(e++, node(1), node(2), t, 100));
        trace.add(preAcceptReq(e++, node(1), node(3), t, 101));
        trace.add(preAcceptReq(e++, node(1), node(4), t, 102));
        trace.add(preAcceptOk(e++, node(2), node(1), t, 100));
        trace.add(preAcceptOk(e++, node(3), node(1), t, 101));
        trace.add(preAcceptOk(e++, node(4), node(1), t, 102));

        int prevSize = 0;
        for (int k = 1; k <= trace.size(); k++) {
            PredicateStateMachine prefixMachine = PredicateStateMachine.replay(trace.prefix(k), StageClassifier.EXTENT);
            int size = prefixMachine.visitedStates().size();
            assertTrue(size >= prevSize, "visited-state count must not shrink as the prefix grows");
            prevSize = size;
        }

        PredicateStateMachine full = new PredicateStateMachine(trace, StageClassifier.EXTENT);
        for (TraceEvent event : trace.events())
            full.apply(event);
        assertEquals(prevSize, full.visitedStates().size());
    }

    @Test
    void replayIsDeterministic() {
        TxnId t = txn(1, 1);
        Trace trace = new Trace(new Trace.Header(2L, N, 1, "test-1.0"));
        long e = 1;
        trace.add(preAcceptReq(e++, node(1), node(2), t, 100));
        trace.add(preAcceptOk(e++, node(2), node(1), t, 100));
        trace.add(preAcceptReq(e++, node(1), node(3), t, 101));
        trace.add(preAcceptOk(e++, node(3), node(1), t, 101));

        Set<String> first = PredicateStateMachine.replay(trace, StageClassifier.EXTENT).visitedStates();
        Set<String> second = PredicateStateMachine.replay(trace, StageClassifier.EXTENT).visitedStates();

        assertEquals(first, second);
    }

    /**
     * The key property this class exists for: two traces with the same final predicate set, that
     * only differ in how two transactions' events interleave, must visit different intermediate
     * joint states along the way. A pure "final predicate checklist" would see these as identical;
     * state coverage must not.
     */
    @Test
    void interleavedTransactionsVisitDifferentIntermediateStatesThanSequential() {
        TxnId a = txn(1, 1);
        TxnId b = txn(5, 1);

        // Sequential: A's PreAccept fully sent+acked before B's PreAccept starts at all.
        Trace sequential = new Trace(new Trace.Header(3L, N, 2, "test-1.0"));
        long e = 1;
        sequential.add(preAcceptReq(e++, node(1), node(2), a, 100));
        sequential.add(preAcceptReq(e++, node(1), node(3), a, 101));
        sequential.add(preAcceptReq(e++, node(1), node(4), a, 102));
        sequential.add(preAcceptOk(e++, node(2), node(1), a, 100));
        sequential.add(preAcceptOk(e++, node(3), node(1), a, 101));
        sequential.add(preAcceptOk(e++, node(4), node(1), a, 102));
        sequential.add(preAcceptReq(e++, node(5), node(6), b, 200));
        sequential.add(preAcceptReq(e++, node(5), node(7), b, 201));
        sequential.add(preAcceptReq(e++, node(5), node(1), b, 202));
        sequential.add(preAcceptOk(e++, node(6), node(5), b, 200));
        sequential.add(preAcceptOk(e++, node(7), node(5), b, 201));
        sequential.add(preAcceptOk(e++, node(1), node(5), b, 202));

        // Interleaved: A and B's requests/acks alternate. Same events, same final state, different order.
        Trace interleaved = new Trace(new Trace.Header(3L, N, 2, "test-1.0"));
        e = 1;
        interleaved.add(preAcceptReq(e++, node(1), node(2), a, 100));
        interleaved.add(preAcceptReq(e++, node(5), node(6), b, 200));
        interleaved.add(preAcceptReq(e++, node(1), node(3), a, 101));
        interleaved.add(preAcceptReq(e++, node(5), node(7), b, 201));
        interleaved.add(preAcceptReq(e++, node(1), node(4), a, 102));
        interleaved.add(preAcceptReq(e++, node(5), node(1), b, 202));
        interleaved.add(preAcceptOk(e++, node(2), node(1), a, 100));
        interleaved.add(preAcceptOk(e++, node(6), node(5), b, 200));
        interleaved.add(preAcceptOk(e++, node(3), node(1), a, 101));
        interleaved.add(preAcceptOk(e++, node(7), node(5), b, 201));
        interleaved.add(preAcceptOk(e++, node(4), node(1), a, 102));
        interleaved.add(preAcceptOk(e++, node(1), node(5), b, 202));

        PredicateStateMachine seqMachine = PredicateStateMachine.replay(sequential, StageClassifier.EXTENT);
        PredicateStateMachine interMachine = PredicateStateMachine.replay(interleaved, StageClassifier.EXTENT);

        Set<String> seqStates = seqMachine.visitedStates();
        Set<String> interStates = interMachine.visitedStates();

        assertNotEquals(seqStates, interStates, "same final predicate set but different interleaving must visit different intermediate states");

        // Neither is a subset of the other: each path visits at least one state the other never does.
        boolean seqHasUnique = seqStates.stream().anyMatch(s -> !interStates.contains(s));
        boolean interHasUnique = interStates.stream().anyMatch(s -> !seqStates.contains(s));
        assertTrue(seqHasUnique, "sequential path should visit a state (both req+acked before B appears) the interleaved path never does");
        assertTrue(interHasUnique, "interleaved path should visit a state (both present, neither acked) the sequential path never does");

        // Both end up at the same final joint state, since the final predicate set is identical.
        List<String> seqList = new ArrayList<>(seqStates);
        List<String> interList = new ArrayList<>(interStates);
        assertEquals(seqList.get(seqList.size() - 1), interList.get(interList.size() - 1));
    }

    /**
     * A crash landing between two message deliveries must be visible in the joint state, not
     * silently dropped - it's a schedule mutation exactly like a swap, and whether a crash lands
     * before/during/after a transaction's progress is exactly the interleaving crash/restart
     * mutations perturb. Compares an otherwise-identical trace with and without a Crash/Recover
     * pair inserted; the crash trace must visit strictly more distinct states, and at least one
     * of them must be parametrized by the crashing node's id.
     */
    @Test
    void crashBetweenEventsProducesAdditionalDistinctStates() {
        TxnId t = txn(1, 1);
        Node.Id crashing = node(5);

        Trace withoutCrash = new Trace(new Trace.Header(5L, N, 1, "test-1.0"));
        long e = 1;
        withoutCrash.add(preAcceptReq(e++, node(1), node(2), t, 100));
        withoutCrash.add(preAcceptReq(e++, node(1), node(3), t, 101));
        withoutCrash.add(preAcceptReq(e++, node(1), node(4), t, 102));
        withoutCrash.add(preAcceptOk(e++, node(2), node(1), t, 100));
        withoutCrash.add(preAcceptOk(e++, node(3), node(1), t, 101));
        withoutCrash.add(preAcceptOk(e++, node(4), node(1), t, 102));

        Trace withCrash = new Trace(new Trace.Header(5L, N, 1, "test-1.0"));
        e = 1;
        withCrash.add(preAcceptReq(e++, node(1), node(2), t, 100));
        withCrash.add(preAcceptReq(e++, node(1), node(3), t, 101));
        withCrash.add(new TraceEvent.Crash(e++, e, crashing));
        withCrash.add(preAcceptReq(e++, node(1), node(4), t, 102));
        withCrash.add(preAcceptOk(e++, node(2), node(1), t, 100));
        withCrash.add(preAcceptOk(e++, node(3), node(1), t, 101));
        withCrash.add(new TraceEvent.Recover(e++, e, crashing));
        withCrash.add(preAcceptOk(e++, node(4), node(1), t, 102));

        Set<String> statesWithoutCrash = PredicateStateMachine.replay(withoutCrash, StageClassifier.EXTENT).visitedStates();
        Set<String> statesWithCrash = PredicateStateMachine.replay(withCrash, StageClassifier.EXTENT).visitedStates();

        assertTrue(statesWithCrash.size() > statesWithoutCrash.size(),
                "the crash/recover pair must introduce additional distinct joint states");
        assertTrue(statesWithCrash.stream().anyMatch(s -> s.contains("crashed:[" + crashing + "]")),
                "at least one visited state must be parametrized by the crashing node's id");
        assertTrue(statesWithCrash.stream().anyMatch(s -> s.startsWith("crashed:[]")),
                "states before the crash and after the recover must show no crashed nodes");
    }

    /**
     * REACHED_COMPLETED is a strictly coarser function of the same underlying counts as EXTENT,
     * so it can never detect more state transitions - only the same or fewer.
     */
    @Test
    void coarserClassifierNeverVisitsMoreStatesThanFinerOne() {
        TxnId t = txn(1, 1);
        Trace trace = new Trace(new Trace.Header(4L, N, 1, "test-1.0"));
        long e = 1;
        for (int to = 2; to <= 7; to++)
            trace.add(preAcceptReq(e++, node(1), node(to), t, 100 + to));
        for (int from = 2; from <= 7; from++)
            trace.add(preAcceptOk(e++, node(from), node(1), t, 100 + from));

        int extentSize = PredicateStateMachine.replay(trace, StageClassifier.EXTENT).visitedStates().size();
        int reachedCompletedSize = PredicateStateMachine.replay(trace, StageClassifier.REACHED_COMPLETED).visitedStates().size();

        assertTrue(reachedCompletedSize <= extentSize);
        assertFalse(trace.isEmpty());
    }
}
