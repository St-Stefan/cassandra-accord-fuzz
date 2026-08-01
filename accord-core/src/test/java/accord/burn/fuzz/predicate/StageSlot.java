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

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Classifies the raw stage names {@link StageExtractor#stageOf} produces (e.g. {@code
 * "PRE_ACCEPT"}, {@code "BEGIN_RECOVER"}) for {@link HistoryMode#CURRENT_STAGE_ONLY}: which ones
 * belong to the classic single-coordinator commit path (and in what order), which belong to a
 * recovery coordinator's escalation instead, and - by simply not appearing in either - which are
 * ignored entirely.
 * <p>
 * Two raw stage names are folded into an earlier tier rather than getting a tier of their own,
 * because they're alternate outcomes of that tier, not new stages, confirmed against the actual
 * Accord coordination classes rather than guessed from the name:
 * <ul>
 *     <li>{@code NOT_ACCEPT} - {@code Accept.NotAccept}, built via {@code Propose.NotAccept}.
 *     A plain (non-recovering) coordinator sends this itself when its own PreAccept round comes
 *     back rejected ({@code CoordinateTransaction.onPreAccepted}), so it isn't recovery-exclusive -
 *     it's an alternate outcome of the ACCEPT tier.</li>
 *     <li>{@code COMMIT_INVALIDATE} - {@code Commit.Invalidate}; a genuine terminal outcome ("it's
 *     fine for this to operate on a non-participating home key, since invalidation is a terminal
 *     state" - {@code Commit.java}) at the same tier as a normal {@code COMMIT}, not a distinct
 *     stage above it.</li>
 * </ul>
 * Recovery-only stages ({@code BEGIN_RECOVER}, {@code BEGIN_INVALIDATE}, {@code RECOVER_AWAIT} -
 * confirmed exclusive to {@code Recover}/{@code Invalidate}, never constructed by uncontended
 * execution) are deliberately <b>not</b> folded into the backbone order at all: a recovery
 * coordinator can be invoked at any point in a transaction's lifetime, concurrently with or after
 * the original coordinator's own progress, so it doesn't have a natural place in a single
 * supplant-chain. They get their own independent slot instead.
 * <p>
 * Everything else (reads, awaits, durability housekeeping, data fetch/repair, status probes) is
 * ignored under {@code CURRENT_STAGE_ONLY} simply by not being listed here - no explicit "ignore"
 * table needed.
 */
public final class StageSlot
{
    private StageSlot() {}

    /** The classic single-coordinator commit path, in protocol order. */
    public static final List<String> BACKBONE_ORDER =
        List.of("PRE_ACCEPT", "ACCEPT", "COMMIT", "APPLY", "INFORM_DURABLE");

    /** Raw stage name -> the backbone tier it's an alternate outcome of. */
    private static final Map<String, String> BACKBONE_ALIAS = Map.of(
        "NOT_ACCEPT", "ACCEPT",
        "COMMIT_INVALIDATE", "COMMIT"
    );

    /** Recovery-coordinator escalation - tracked as one independent slot, never part of the backbone order. */
    public static final Set<String> RECOVERY_STAGES = Set.of("BEGIN_RECOVER", "BEGIN_INVALIDATE", "RECOVER_AWAIT");

    private static final Map<String, Set<String>> RAW_STAGES_FOR_BACKBONE = buildRawStagesForBackbone();
    private static final Set<String> ALL_RELEVANT_STAGES = buildAllRelevantStages();

    private static Map<String, Set<String>> buildRawStagesForBackbone()
    {
        Map<String, Set<String>> result = new LinkedHashMap<>();
        for (String name : BACKBONE_ORDER)
            result.put(name, new LinkedHashSet<>(Set.of(name)));
        BACKBONE_ALIAS.forEach((alias, canonical) -> result.get(canonical).add(alias));
        return result;
    }

    private static Set<String> buildAllRelevantStages()
    {
        Set<String> result = new LinkedHashSet<>();
        for (Set<String> raw : RAW_STAGES_FOR_BACKBONE.values())
            result.addAll(raw);
        result.addAll(RECOVERY_STAGES);
        return result;
    }

    /** Every raw stage name that counts toward {@code backboneName}'s tier (itself plus any aliases). */
    public static Set<String> rawStagesFor(String backboneName)
    {
        return RAW_STAGES_FOR_BACKBONE.get(backboneName);
    }

    /**
     * True for any raw stage name that participates in the predicate abstraction at all - a
     * backbone tier (or one of its aliases) or the recovery family. False for reads, awaits,
     * durability housekeeping, data fetch/repair, and status probes (e.g. {@code CHECK_STATUS} -
     * observed making up 41% of the messages in a real recorded trace, dwarfing every backbone
     * stage combined, since it's fired by the progress log's watchdog on a timer independent of
     * whether anything is actually wrong). Used by both {@link HistoryMode}s: {@link
     * HistoryMode#FULL_HISTORY} calls this directly to drop irrelevant stages without collapsing
     * history; {@link HistoryMode#CURRENT_STAGE_ONLY} gets the same filtering for free since it
     * only ever looks up {@link #BACKBONE_ORDER} and {@link #RECOVERY_STAGES} directly and never
     * consults anything else the walker recorded.
     */
    public static boolean isRelevant(String rawStage)
    {
        return ALL_RELEVANT_STAGES.contains(rawStage);
    }
}