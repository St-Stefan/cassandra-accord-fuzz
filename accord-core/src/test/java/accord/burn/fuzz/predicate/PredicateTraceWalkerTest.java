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

import java.util.List;

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
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PredicateTraceWalkerTest
{
    private static final int N = 7;
    private static final int QUORUM = 4;
    private static final long NO_ID = Integer.MIN_VALUE;

    private static Node.Id node(int i) { return new Node.Id(i); }

    private static TxnId txn(int id)
    {
        return new TxnId(1, id, Kind.Write, Domain.Key, node(1));
    }

    // ===== StageExtractor =====

    @Test
    void stageNamingStripsReqRspSuffix()
    {
        assertEquals("PRE_ACCEPT", StageExtractor.stageOf(StandardMessage.PRE_ACCEPT_REQ));
        assertEquals("PRE_ACCEPT", StageExtractor.stageOf(StandardMessage.PRE_ACCEPT_RSP));
        assertEquals("ACCEPT", StageExtractor.stageOf(StandardMessage.ACCEPT_REQ));
        assertTrue(StageExtractor.isRequest(StandardMessage.ACCEPT_REQ));
        assertTrue(StageExtractor.isReply(StandardMessage.ACCEPT_RSP));
    }

    @Test
    void genericRepliesDoNotNameTheirOwnStage()
    {
        assertFalse(StageExtractor.namesOwnStage(StandardMessage.SIMPLE_RSP));
        assertFalse(StageExtractor.namesOwnStage(StandardMessage.FAILURE_RSP));
        assertTrue(StageExtractor.namesOwnStage(StandardMessage.ACCEPT_RSP));
    }

    // ===== PredicateTraceWalker =====

    @Test
    void countsDistinctDestinationsAndSources()
    {
        TxnId t = txn(1);
        Trace trace = new Trace(new Trace.Header(1L, N, 1, "test-1.0"));
        long eventId = 1, ts = 1, msgId = 1;

        // PreAccept sent to all 7, only 5 reply (a QUORUM but not ALL)
        for (int to = 1; to <= N; to++)
            trace.add(new TraceEvent.Deliver(eventId++, ts++, msgId++, node(0), node(to),
                    StandardMessage.PRE_ACCEPT_REQ, t, "PreAccept", 100 + to, NO_ID, 0));
        for (int from = 1; from <= 5; from++)
            trace.add(new TraceEvent.Deliver(eventId++, ts++, msgId++, node(from), node(0),
                    StandardMessage.PRE_ACCEPT_RSP, t, "PreAcceptOk", NO_ID, 100 + from, 0));

        PredicateTraceWalker walker = PredicateTraceWalker.of(trace);

        assertEquals(7, walker.sentCount(t, "PRE_ACCEPT"));
        assertEquals(5, walker.ackedCount(t, "PRE_ACCEPT"));
        assertEquals(0, walker.sentCount(t, "ACCEPT"));
    }

    /**
     * Reproduces the observed gap: Accept replies whose own Deliver carries txnId == null.
     * The walker must recover both the txnId and the stage via requestId/replyId correlation,
     * the same mechanism TraceRecorder itself uses (see TraceRecorder.recordDeliver).
     */
    @Test
    void resolvesNullTxnIdOnAcceptRepliesViaRequestCorrelation()
    {
        TxnId t = txn(2);
        Trace trace = new Trace(new Trace.Header(2L, N, 1, "test-1.0"));
        long eventId = 1, ts = 1, msgId = 1;
        long requestId = 500;

        trace.add(new TraceEvent.Deliver(eventId++, ts++, msgId++, node(0), node(1),
                StandardMessage.ACCEPT_REQ, t, "Accept", requestId, NO_ID, 0));
        // txnId == null here on purpose, mirroring what's actually observed on Accept replies
        trace.add(new TraceEvent.Deliver(eventId++, ts++, msgId++, node(1), node(0),
                StandardMessage.ACCEPT_RSP, null, "AcceptOk", NO_ID, requestId, 0));

        PredicateTraceWalker walker = PredicateTraceWalker.of(trace);

        assertEquals(1, walker.sentCount(t, "ACCEPT"));
        assertEquals(1, walker.ackedCount(t, "ACCEPT"));
    }

    @Test
    void resolvesGenericReplyStageViaRequestCorrelation()
    {
        TxnId t = txn(3);
        Trace trace = new Trace(new Trace.Header(3L, N, 1, "test-1.0"));
        long requestId = 700;

        trace.add(new TraceEvent.Deliver(1, 1, 1, node(0), node(1),
                StandardMessage.COMMIT_REQ, t, "Commit", requestId, NO_ID, 0));
        trace.add(new TraceEvent.Deliver(2, 2, 2, node(1), node(0),
                StandardMessage.SIMPLE_RSP, null, "SimpleReply", NO_ID, requestId, 0));

        PredicateTraceWalker walker = PredicateTraceWalker.of(trace);

        assertEquals(1, walker.sentCount(t, "COMMIT"));
        assertEquals(1, walker.ackedCount(t, "COMMIT"));
    }

    /**
     * Coverage of a single trace is built by replaying it event-by-event; feeding growing
     * prefixes must never make counts shrink, and the final prefix must match a one-shot walk.
     */
    @Test
    void countsGrowMonotonicallyOverIncreasingPrefixes()
    {
        TxnId t = txn(4);
        Trace trace = new Trace(new Trace.Header(4L, N, 1, "test-1.0"));
        long eventId = 1, ts = 1, msgId = 1;
        for (int to = 1; to <= N; to++)
            trace.add(new TraceEvent.Deliver(eventId++, ts++, msgId++, node(0), node(to),
                    StandardMessage.PRE_ACCEPT_REQ, t, "PreAccept", 100 + to, NO_ID, 0));
        for (int from = 1; from <= N; from++)
            trace.add(new TraceEvent.Deliver(eventId++, ts++, msgId++, node(from), node(0),
                    StandardMessage.PRE_ACCEPT_RSP, t, "PreAcceptOk", NO_ID, 100 + from, 0));

        int prevSent = 0, prevAcked = 0;
        for (int k = 1; k <= trace.size(); k++)
        {
            PredicateTraceWalker prefixWalker = PredicateTraceWalker.of(trace.prefix(k));
            int sent = prefixWalker.sentCount(t, "PRE_ACCEPT");
            int acked = prefixWalker.ackedCount(t, "PRE_ACCEPT");
            assertTrue(sent >= prevSent && acked >= prevAcked, "counts must not shrink as the prefix grows");
            prevSent = sent;
            prevAcked = acked;
        }
        assertEquals(N, prevSent);
        assertEquals(N, prevAcked);
    }

    // ===== StageClassifier =====

    @Test
    void extentClassifiesBothDirections()
    {
        assertEquals(List.of(Extent.ALL, Extent.QUORUM),
                     StageClassifier.EXTENT.classify(7, 5, QUORUM, N));
        assertEquals(List.of(Extent.NONE, Extent.NONE),
                     StageClassifier.EXTENT.classify(0, 0, QUORUM, N));
        assertEquals(List.of(Extent.SUBSET, Extent.QUORUM),
                     StageClassifier.EXTENT.classify(2, 4, QUORUM, N));
    }

    @Test
    void reachedCompletedIsCoarserThanExtent()
    {
        assertEquals(List.of(true, false), StageClassifier.REACHED_COMPLETED.classify(1, 2, QUORUM, N));
        assertEquals(List.of(true, true), StageClassifier.REACHED_COMPLETED.classify(7, 5, QUORUM, N));
        assertEquals(List.of(false, false), StageClassifier.REACHED_COMPLETED.classify(0, 0, QUORUM, N));
    }
}
