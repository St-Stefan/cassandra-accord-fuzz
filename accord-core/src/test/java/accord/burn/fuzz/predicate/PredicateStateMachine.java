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
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import accord.burn.fuzz.trace.Trace;
import accord.burn.fuzz.trace.TraceEvent;
import accord.local.Node;
import accord.primitives.TxnId;

/**
 * Replays a {@link Trace} event by event and, after each event, records the <b>joint</b> abstract
 * state across all transactions - not just the final predicate set once the trace is done. This
 * is what makes the resulting coverage "state coverage" rather than a small predicate checklist:
 * the same final predicate set reached via different interleavings of two transactions (e.g. "A
 * finishes PreAccept before B starts" vs "A and B both reach PreAccept-QUORUM at once") produces
 * different intermediate states, and that interleaving structure is exactly what the fuzzer's
 * schedule mutations (swap/crash/restart) perturb.
 * <p>
 * The joint state at a point in the trace is: for every transaction touched so far (identified by
 * its {@link TxnNormalizer} id, not its raw seed-dependent {@link TxnId}), the classification of
 * every stage it has touched so far, sorted for stability regardless of delivery order - plus
 * which nodes are currently crashed, since a crash landing before, during, or after a
 * transaction's progress is exactly the kind of interleaving crash/restart mutations perturb, and
 * needs to be distinguished the same way message interleaving is. This is rendered as a canonical
 * string and used directly as the state key - unlike {@code TlcGuider}, which MD5-hashes a large
 * free-text TLC state block down to a fixed-size key, the state here is already small (a handful
 * of transactions x stages), so hashing it would only add collision risk for no benefit.
 */
public class PredicateStateMachine
{
    private final PredicateTraceWalker walker = new PredicateTraceWalker();
    // Nodes currently crashed (a Crash seen with no later Recover). TreeSet so the rendered state
    // key is always in node-id order regardless of the order Crash/Recover events arrived in -
    // see Node.Id.compareTo, which sorts purely on the numeric id.
    private final Set<Node.Id> crashedNodes = new TreeSet<>();
    private final Map<TxnId, Integer> normalizedIds;
    private final StageClassifier classifier;
    private final HistoryMode historyMode;
    private final int quorum;
    private final int observableNodeCount;

    private final List<String> visited = new ArrayList<>();
    private String lastStateKey;

    /** Defaults to {@link HistoryMode#FULL_HISTORY}, the original behavior. */
    public PredicateStateMachine(Trace trace, StageClassifier classifier)
    {
        this(trace, classifier, HistoryMode.FULL_HISTORY);
    }

    /**
     * @param trace the full trace this machine will replay - only used up front to compute
     *              {@link TxnNormalizer} ids and to read the node count from the trace header;
     *              events still need to be fed in via {@link #apply(TraceEvent)} (or {@link #replay}).
     */
    public PredicateStateMachine(Trace trace, StageClassifier classifier, HistoryMode historyMode)
    {
        this.normalizedIds = TxnNormalizer.normalize(trace);
        this.classifier = classifier;
        this.historyMode = historyMode;
        int clusterSize = trace.header().nodeCount();
        // Majority quorum, matching the convention already used in PredicateReplayTest; the
        // trace format doesn't carry the actual per-shard electorate, so this is an
        // approximation, not derived from Topology.
        this.quorum = clusterSize / 2 + 1;
        // The "n" fed into Extent classification is NOT clusterSize: a coordinator never sends
        // itself a network message (GuidedPendingQueue.shouldBypassReplay drops any packet where
        // dst.equals(src)), so the maximum sent/acked count observable in a trace is always
        // clusterSize - 1, never clusterSize. Using clusterSize here made Extent.ALL unreachable -
        // e.g. a stage acked by every other node (count == clusterSize - 1) was classified QUORUM,
        // never ALL, because count < clusterSize always held.
        this.observableNodeCount = clusterSize - 1;
    }

    /** Convenience for offline/one-shot use (tests, analysis of a saved trace). */
    public static PredicateStateMachine replay(Trace trace, StageClassifier classifier)
    {
        return replay(trace, classifier, HistoryMode.FULL_HISTORY);
    }

    public static PredicateStateMachine replay(Trace trace, StageClassifier classifier, HistoryMode historyMode)
    {
        PredicateStateMachine machine = new PredicateStateMachine(trace, classifier, historyMode);
        for (TraceEvent event : trace.events())
            machine.apply(event);
        return machine;
    }

    public void apply(TraceEvent event)
    {
        walker.apply(event);
        if (event instanceof TraceEvent.Crash)
            crashedNodes.add(((TraceEvent.Crash) event).node);
        else if (event instanceof TraceEvent.Recover)
            crashedNodes.remove(((TraceEvent.Recover) event).node);
        String stateKey = jointStateKey();
        if (lastStateKey == null || !lastStateKey.equals(stateKey))
        {
            lastStateKey = stateKey;
            visited.add(stateKey);
        }
    }

    /** Every distinct joint state visited over the course of the replay so far, in visit order. */
    public Set<String> visitedStates()
    {
        return new LinkedHashSet<>(visited);
    }

    private String jointStateKey()
    {
        return historyMode == HistoryMode.CURRENT_STAGE_ONLY ? jointStateKeyCurrentStageOnly() : jointStateKeyFullHistory();
    }

    private String jointStateKeyFullHistory()
    {
        List<String> perTxn = new ArrayList<>();
        for (TxnId txnId : walker.transactions())
        {
            Integer normId = normalizedIds.get(txnId);
            if (normId == null)
                continue; // not resolvable via TxnNormalizer's PreAccept-based grouping; skip rather than guess

            List<String> stages = new ArrayList<>();
            for (String stage : walker.stagesFor(txnId))
                if (StageSlot.isRelevant(stage))
                    stages.add(stage);
            Collections.sort(stages);

            StringBuilder sb = new StringBuilder("t").append(normId);
            for (String stage : stages)
            {
                int sent = walker.sentCount(txnId, stage);
                int acked = walker.ackedCount(txnId, stage);
                Object classified = classifier.classify(sent, acked, quorum, observableNodeCount);
                sb.append('|').append(stage).append(':').append(classified);
            }
            perTxn.add(sb.toString());
        }
        Collections.sort(perTxn);
        return "crashed:" + crashedNodes + perTxn;
    }

    /**
     * {@link HistoryMode#CURRENT_STAGE_ONLY}: each transaction contributes exactly two slots
     * instead of one entry per stage ever touched - its current (highest-{@link
     * StageSlot#BACKBONE_ORDER}) backbone tier, and a separate recovery slot. Superseded backbone
     * tiers are dropped entirely rather than accumulating; stages that are neither backbone nor
     * recovery (reads, durability housekeeping, data fetch/repair, status probes) are ignored by
     * construction - they're simply never looked up.
     * <p>
     * "Current" is computed by scanning {@link StageSlot#BACKBONE_ORDER} in increasing protocol
     * order and keeping the last (i.e. highest) tier touched at all - since {@link
     * PredicateTraceWalker} only ever accumulates (a stage, once touched, stays touched), this is
     * automatically a monotonic non-decreasing watermark across the replay: a late/duplicate event
     * for an already-superseded tier can't regress it, because that tier was already touched
     * before and touched is not re-evaluated per-event.
     */
    private String jointStateKeyCurrentStageOnly()
    {
        List<String> perTxn = new ArrayList<>();
        for (TxnId txnId : walker.transactions())
        {
            Integer normId = normalizedIds.get(txnId);
            if (normId == null)
                continue;

            Set<String> touched = walker.stagesFor(txnId);

            String currentBackbone = null;
            for (String candidate : StageSlot.BACKBONE_ORDER)
                if (!Collections.disjoint(touched, StageSlot.rawStagesFor(candidate)))
                    currentBackbone = candidate;

            String backboneEntry;
            if (currentBackbone == null)
                backboneEntry = "backbone:NONE";
            else
            {
                Set<String> rawStages = StageSlot.rawStagesFor(currentBackbone);
                Object classified = classifier.classify(walker.sentCount(txnId, rawStages),
                                                          walker.ackedCount(txnId, rawStages),
                                                          quorum, observableNodeCount);
                backboneEntry = "backbone:" + currentBackbone + ":" + classified;
            }

            String recoveryEntry;
            if (Collections.disjoint(touched, StageSlot.RECOVERY_STAGES))
                recoveryEntry = "recovery:NONE";
            else
            {
                Object classified = classifier.classify(walker.sentCount(txnId, StageSlot.RECOVERY_STAGES),
                                                          walker.ackedCount(txnId, StageSlot.RECOVERY_STAGES),
                                                          quorum, observableNodeCount);
                recoveryEntry = "recovery:" + classified;
            }

            perTxn.add("t" + normId + "|" + backboneEntry + "|" + recoveryEntry);
        }
        Collections.sort(perTxn);
        return "crashed:" + crashedNodes + perTxn;
    }
}
