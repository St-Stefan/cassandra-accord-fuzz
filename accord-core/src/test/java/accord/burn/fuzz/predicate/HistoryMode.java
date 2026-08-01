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

/**
 * Orthogonal to {@link StageClassifier} (which controls how coarse a single stage's label is):
 * this controls how much of a transaction's stage history stays in {@link PredicateStateMachine}'s
 * joint-state key.
 */
public enum HistoryMode
{
    /**
     * Every stage a transaction has ever touched stays in the key forever, alongside every other
     * stage it has touched - the original behavior. A stage's contribution never changes once
     * classified as {@code ALL}/{@code ALL} (or any other terminal-looking value), but a stray
     * straggler ack for an already-superseded stage can still nudge its {@link Extent} up, which
     * forks the key even though it can no longer affect the transaction's actual progress.
     */
    FULL_HISTORY,

    /**
     * Each transaction contributes exactly two slots to the key: its current (highest-reached)
     * classic backbone stage, and a separate recovery-escalation slot - see {@link StageSlot}.
     * A later backbone stage supplants the earlier one entirely rather than accumulating
     * alongside it; messages that don't belong to either family (reads, durability housekeeping,
     * data fetch/repair) are ignored.
     */
    CURRENT_STAGE_ONLY
}