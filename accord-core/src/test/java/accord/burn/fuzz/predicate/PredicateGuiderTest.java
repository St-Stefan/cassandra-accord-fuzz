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
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PredicateGuiderTest {

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

    @Test
    void firstCheckReturnsEveryStateVisitedInThatTrace() {
        TxnId t = txn(1, 1);
        Trace trace = new Trace(new Trace.Header(1L, N, 1, "test-1.0"));
        long e = 1;
        trace.add(preAcceptReq(e++, node(1), node(2), t, 100));
        trace.add(preAcceptReq(e++, node(1), node(3), t, 101));
        trace.add(preAcceptOk(e++, node(2), node(1), t, 100));
        trace.add(preAcceptOk(e++, node(3), node(1), t, 101));

        int expected = PredicateStateMachine.replay(trace, StageClassifier.EXTENT).visitedStates().size();

        PredicateGuider guider = new PredicateGuider(StageClassifier.EXTENT);
        assertEquals(expected, guider.check(trace));
        assertEquals(expected, guider.totalSeenStates());
    }

    @Test
    void repeatedCheckOnSameTraceFindsNoNewStates() {
        TxnId t = txn(1, 1);
        Trace trace = new Trace(new Trace.Header(2L, N, 1, "test-1.0"));
        long e = 1;
        trace.add(preAcceptReq(e++, node(1), node(2), t, 100));
        trace.add(preAcceptOk(e++, node(2), node(1), t, 100));

        PredicateGuider guider = new PredicateGuider(StageClassifier.EXTENT);
        int first = guider.check(trace);
        int totalAfterFirst = guider.totalSeenStates();

        assertEquals(0, guider.check(trace));
        assertEquals(totalAfterFirst, guider.totalSeenStates());
        assertTrue(first > 0);
    }

    /**
     * Two traces that share some intermediate states (see
     * PredicateStateMachineTest#interleavedTransactionsVisitDifferentIntermediateStatesThanSequential
     * for the full derivation of why sequential vs. interleaved delivery order overlaps on some
     * joint states but not others) - check() on the second trace must report only the states not
     * already contributed by the first, and totalSeenStates() must accumulate across both calls.
     */
    @Test
    void secondTraceOnlyContributesItsNovelStates() {
        TxnId a = txn(1, 1);
        TxnId b = txn(5, 1);

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

        Set<String> seqStates = PredicateStateMachine.replay(sequential, StageClassifier.EXTENT).visitedStates();
        Set<String> interStates = PredicateStateMachine.replay(interleaved, StageClassifier.EXTENT).visitedStates();
        int expectedNovelFromInterleaved = (int) interStates.stream().filter(s -> !seqStates.contains(s)).count();
        assertTrue(expectedNovelFromInterleaved > 0, "test setup should produce at least one genuinely novel state");
        assertTrue(expectedNovelFromInterleaved < interStates.size(), "test setup should also produce at least one shared state");

        PredicateGuider guider = new PredicateGuider(StageClassifier.EXTENT);
        assertEquals(seqStates.size(), guider.check(sequential));
        assertEquals(seqStates.size(), guider.totalSeenStates());

        assertEquals(expectedNovelFromInterleaved, guider.check(interleaved));
        assertEquals(seqStates.size() + expectedNovelFromInterleaved, guider.totalSeenStates());
    }
}
