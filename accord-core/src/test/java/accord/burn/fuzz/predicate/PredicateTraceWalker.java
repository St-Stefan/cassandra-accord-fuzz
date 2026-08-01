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

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import accord.burn.fuzz.trace.Trace;
import accord.burn.fuzz.trace.TraceEvent;
import accord.local.Node;
import accord.primitives.TxnId;

/**
 * Walks a {@link Trace} (or a prefix of one) and, for every (transaction, stage) pair, counts
 * the distinct destinations a request was sent to and the distinct sources that replied. This
 * is "Level 1" of the predicate abstraction ladder - raw stage counts, no classification applied.
 * <p>
 * Feed events one at a time via {@link #apply(TraceEvent)} so the same walker instance can be
 * reused by an incremental state machine later; {@link #of(Trace)} is a convenience for offline
 * use (tests, one-shot analysis of a saved trace).
 * <p>
 * Two things every reply needs that its own {@code Deliver} event may not carry directly:
 * <ul>
 *     <li>a {@code txnId} - null on some reply types (observed on Accept replies) because
 *     {@code TxnIdExtractor} can't find a {@code txnId} field via reflection on that reply class;</li>
 *     <li>a stage - {@code SIMPLE_RSP}/{@code FAILURE_RSP} are generic replies whose name doesn't
 *     identify a stage at all.</li>
 * </ul>
 * Both are resolved the same way: the matching request is cached when seen and looked up via
 * the reply's {@code replyId}.
 * <p>
 * {@code requestId} is <b>not</b> globally unique - {@code NodeSink.nextMessageId} is a plain
 * counter starting at 0 on every node, so two different nodes' requests can carry the same
 * numeric id. The cache is therefore keyed by {@code (sender, requestId)}, not by {@code
 * requestId} alone; a reply's {@code (d.to, d.replyId)} is always the matching key, since {@code
 * d.to} on a reply is the node that sent the original request (see {@code Packet}'s reply
 * constructor).
 */
public class PredicateTraceWalker
{
    /** Sentinel used throughout the fuzz trace code for "no id" (see TraceRecorder, Fuzzer). */
    private static final long NO_ID = Integer.MIN_VALUE;

    private record Pending(TxnId txnId, String stage) {}
    private record PendingKey(Node.Id node, long requestId) {}

    private final Map<PendingKey, Pending> pendingByRequestId = new LinkedHashMap<>();
    private final Map<TxnId, Map<String, Set<Node.Id>>> sent = new LinkedHashMap<>();
    private final Map<TxnId, Map<String, Set<Node.Id>>> acked = new LinkedHashMap<>();

    public static PredicateTraceWalker of(Trace trace)
    {
        PredicateTraceWalker walker = new PredicateTraceWalker();
        for (TraceEvent event : trace.events())
            walker.apply(event);
        return walker;
    }

    public void apply(TraceEvent event)
    {
        if (!(event instanceof TraceEvent.Deliver))
            return;
        TraceEvent.Deliver d = (TraceEvent.Deliver) event;
        if (d.messageType == null)
            return; // synthetic mutation events carry no message type

        if (StageExtractor.isRequest(d.messageType))
            applyRequest(d);
        else if (StageExtractor.isReply(d.messageType))
            applyReply(d);
    }

    private void applyRequest(TraceEvent.Deliver d)
    {
        if (d.txnId == null)
            return; // requests are expected to always carry a txnId; nothing to attribute this to
        String stage = StageExtractor.stageOf(d.messageType);
        record(sent, d.txnId, stage, d.to);
        if (d.requestId != NO_ID)
            pendingByRequestId.put(new PendingKey(d.from, d.requestId), new Pending(d.txnId, stage));
    }

    private void applyReply(TraceEvent.Deliver d)
    {
        Pending origin = d.replyId != NO_ID ? pendingByRequestId.get(new PendingKey(d.to, d.replyId)) : null;

        TxnId txnId = d.txnId != null ? d.txnId : (origin != null ? origin.txnId() : null);
        if (txnId == null)
            return; // can't attribute this reply to a transaction, drop it

        String stage = StageExtractor.namesOwnStage(d.messageType)
                        ? StageExtractor.stageOf(d.messageType)
                        : (origin != null ? origin.stage() : null);
        if (stage == null)
            return; // generic reply with no correlated request, drop it

        record(acked, txnId, stage, d.from);
    }

    private static void record(Map<TxnId, Map<String, Set<Node.Id>>> into, TxnId txnId, String stage, Node.Id node)
    {
        into.computeIfAbsent(txnId, k -> new LinkedHashMap<>())
            .computeIfAbsent(stage, k -> new LinkedHashSet<>())
            .add(node);
    }

    public Set<TxnId> transactions()
    {
        Set<TxnId> all = new LinkedHashSet<>(sent.keySet());
        all.addAll(acked.keySet());
        return all;
    }

    public Set<String> stagesFor(TxnId txnId)
    {
        Set<String> stages = new LinkedHashSet<>();
        Map<String, Set<Node.Id>> s = sent.get(txnId);
        if (s != null) stages.addAll(s.keySet());
        Map<String, Set<Node.Id>> a = acked.get(txnId);
        if (a != null) stages.addAll(a.keySet());
        return stages;
    }

    public int sentCount(TxnId txnId, String stage)
    {
        return countOf(sent, txnId, stage);
    }

    public int ackedCount(TxnId txnId, String stage)
    {
        return countOf(acked, txnId, stage);
    }

    /**
     * Distinct destinations across all of {@code stages} combined (a node counted once even if it
     * appears under more than one of them) - used by {@link StageSlot}-aliased tiers, e.g. folding
     * {@code NOT_ACCEPT} into the {@code ACCEPT} tier's count rather than tracking it separately.
     */
    public int sentCount(TxnId txnId, Collection<String> stages)
    {
        return unionCount(sent, txnId, stages);
    }

    public int ackedCount(TxnId txnId, Collection<String> stages)
    {
        return unionCount(acked, txnId, stages);
    }

    private static int unionCount(Map<TxnId, Map<String, Set<Node.Id>>> from, TxnId txnId, Collection<String> stages)
    {
        Map<String, Set<Node.Id>> byStage = from.get(txnId);
        if (byStage == null)
            return 0;
        Set<Node.Id> union = new HashSet<>();
        for (String stage : stages)
        {
            Set<Node.Id> nodes = byStage.get(stage);
            if (nodes != null)
                union.addAll(nodes);
        }
        return union.size();
    }

    /** {@code stage -> [sentCount, ackedCount]} for every stage this transaction has touched. */
    public Map<String, int[]> countsFor(TxnId txnId)
    {
        Map<String, int[]> result = new LinkedHashMap<>();
        for (String stage : stagesFor(txnId))
            result.put(stage, new int[]{ sentCount(txnId, stage), ackedCount(txnId, stage) });
        return result;
    }

    private static int countOf(Map<TxnId, Map<String, Set<Node.Id>>> from, TxnId txnId, String stage)
    {
        Map<String, Set<Node.Id>> byStage = from.get(txnId);
        if (byStage == null) return 0;
        Set<Node.Id> nodes = byStage.get(stage);
        return nodes == null ? 0 : nodes.size();
    }
}
