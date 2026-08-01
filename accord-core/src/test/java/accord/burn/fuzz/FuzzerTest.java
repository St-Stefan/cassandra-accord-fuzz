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

package accord.burn.fuzz;

import org.junit.jupiter.api.Test;

import accord.burn.fuzz.predicate.HistoryMode;
import accord.burn.fuzz.predicate.StageClassifier;

public class FuzzerTest {

    @Test
    public void testBasicFuzzLoop() {
        Fuzzer fuzzer = new Fuzzer(
                42L,    // seed
                7,      // numNodes
                3,      // operations
                3,      // concurrency
                5000,   // iterations
                1,      // seedPopulationSize
                1,      // mutationsPerTrace
                1,      // crashQuota
                300     // traceEventBudget
        );
        fuzzer.run();
    }

    /**
     * TLC-guided run. Requires a TLC server running at localhost:2023.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.testGuidedFuzz"
     */
    @Test
    public void testGuidedFuzz() {
        Fuzzer fuzzer = new Fuzzer(
                42L,            // seed
                7,              // numNodes
                3,              // operations
                1,              // concurrency
                5000,           // iterations
                20,              // seedPopulationSize
                1,              // mutationsPerTrace (per-new-state multiplier)
                1,              // crashQuota
                500,            // traceEventBudget
                0L,             // maxDurationMs (unlimited)
                "localhost:2023",
                true,           // guided (energy-based mutation)
                700,            // maxQueueSize
                1000             // reseedFrequency
        );
        fuzzer.run();
    }

    /**
     * Long exploration run. Execute via Gradle CLI to avoid IDE memory pressure:
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.testLongExploration"
     */
    @Test
    public void testLongExploration1() {
        long time = 12* 60 * 60 * 1000;
            Fuzzer fuzzer = new Fuzzer(
                    123L,            // seed
                    7,              // numNodes
                    3,              // operations
                    1,              // concurrency
                    Integer.MAX_VALUE,           // iterations
                    40,              // seedPopulationSize
                    1,              // mutationsPerTrace (per-new-state multiplier)
                    1,              // crashQuota
                    500,            // traceEventBudget
                    time,             // maxDurationMs (unlimited)
                    "localhost:2023",
                    false,           // guided (energy-based mutation)

                    700,            // maxQueueSize
                    0             // reseedFrequency
            );
            fuzzer.run();
    }

    /**
     * Pure random schedule run: every iteration generates a fresh random schedule via ModelFuzz-style
     * schedule generation. No mutation feedback loop. Requires TLC at localhost:2023 for coverage tracking.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.testRandomSchedule"
     */
    @Test
    public void testRandomSchedule() {
        long time = 12 * 60 * 60 * 1000;
        Fuzzer fuzzer = new Fuzzer(
                123L,            // seed
                7,              // numNodes
                3,              // operations
                1,              // concurrency
                Integer.MAX_VALUE,
                40,             // seedPopulationSize
                1,              // mutationsPerTrace (unused in randomSchedule mode)
                1,              // crashQuota
                500,            // traceEventBudget
                time,
                "localhost:2023",
                false,          // guided (no mutation-based guidance)
                700,            // maxQueueSize (unused in randomSchedule mode)
                0,              // reseedFrequency (unused in randomSchedule mode)
                true            // randomSchedule
        );
        fuzzer.run();
    }

    /**
     * Predicate-guided run: mutation energy is driven by {@link accord.burn.fuzz.predicate.PredicateGuider}
     * instead of TLC. A TLC server address is still supplied so TLC coverage is computed and
     * logged every iteration too (session_*.coverage.csv) purely for measurement/comparison
     * against session_*.predicate_coverage.csv - it does not drive any mutation decision here.
     * Requires a TLC server running at localhost:2023 (for the comparison data only).
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.testPredicateGuidedFuzz"
     */
    @Test
    public void testPredicateGuidedFuzz() {
        long time = 8 * 60 * 60 * 1000;
        Fuzzer fuzzer = new Fuzzer(
                123L,            // seed
                7,              // numNodes
                3,              // operations
                1,              // concurrency
                Integer.MAX_VALUE, // iterations
                40,             // seedPopulationSize
                1,              // mutationsPerTrace (per-new-state multiplier)
                1,              // crashQuota
                500,            // traceEventBudget
                time,           // maxDurationMs
                "localhost:2023", // TLC address - coverage tracking only, does not drive mutation here
                true,           // guided (energy-based mutation)
                700,            // maxQueueSize
                0,              // reseedFrequency
                false,          // randomSchedule
                true            // usePredicateGuidance - PredicateGuider drives mutation energy, not TLC
        );
        fuzzer.run();
    }

    /**
     * Same as {@link #testPredicateGuidedFuzz} but with {@link HistoryMode#CURRENT_STAGE_ONLY}:
     * each transaction contributes its current backbone stage plus a separate recovery slot,
     * instead of every stage it has ever touched. Run side by side with testPredicateGuidedFuzz
     * to compare predicate_coverage.csv growth between the two history modes on the same setup.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.testPredicateGuidedFuzzCurrentStageOnly"
     */
    @Test
    public void testPredicateGuidedFuzzCurrentStageOnly() {
        long time = 8 * 60 * 60 * 1000;
        Fuzzer fuzzer = new Fuzzer(
                123L,            // seed
                7,              // numNodes
                3,              // operations
                1,              // concurrency
                Integer.MAX_VALUE, // iterations
                40,             // seedPopulationSize
                1,              // mutationsPerTrace (per-new-state multiplier)
                1,              // crashQuota
                500,            // traceEventBudget
                time,           // maxDurationMs
                "localhost:2023", // TLC address - coverage tracking only, does not drive mutation here
                true,           // guided (energy-based mutation)
                700,            // maxQueueSize
                0,              // reseedFrequency
                false,          // randomSchedule
                true,           // usePredicateGuidance - PredicateGuider drives mutation energy, not TLC
                HistoryMode.CURRENT_STAGE_ONLY
        );
        fuzzer.run();
    }

    /**
     * Same as {@link #testPredicateGuidedFuzz} but with {@link StageClassifier#REACHED_COMPLETED}
     * instead of {@link StageClassifier#EXTENT}: each stage collapses to reached/completed
     * booleans rather than a four-way cardinality class. Since REACHED_COMPLETED is monotonic
     * (a straggler ack arriving after a stage is superseded can't un-reach or un-complete it),
     * this removes the stale-stage noise FULL_HISTORY + EXTENT is prone to, while still keeping
     * every stage a transaction has touched in the key (unlike CURRENT_STAGE_ONLY).
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.testPredicateGuidedFuzzReachedCompleted"
     */
    @Test
    public void testPredicateGuidedFuzzReachedCompleted() {
        long time = 8 * 60 * 60 * 1000;
        Fuzzer fuzzer = new Fuzzer(
                123L,            // seed
                7,              // numNodes
                3,              // operations
                1,              // concurrency
                Integer.MAX_VALUE, // iterations
                40,             // seedPopulationSize
                1,              // mutationsPerTrace (per-new-state multiplier)
                1,              // crashQuota
                500,            // traceEventBudget
                time,           // maxDurationMs
                "localhost:2023", // TLC address - coverage tracking only, does not drive mutation here
                true,           // guided (energy-based mutation)
                700,            // maxQueueSize
                0,              // reseedFrequency
                false,          // randomSchedule
                true,           // usePredicateGuidance - PredicateGuider drives mutation energy, not TLC
                HistoryMode.FULL_HISTORY,
                StageClassifier.REACHED_COMPLETED
        );
        fuzzer.run();
    }

    @Test
    public void testLongExploration2() {
        long time = 12* 60 * 60 * 1000;
        Fuzzer fuzzer = new Fuzzer(
                123L,            // seed
                7,              // numNodes
                3,              // operations
                1,              // concurrency
                Integer.MAX_VALUE,           // iterations
                40,              // seedPopulationSize
                1,              // mutationsPerTrace (per-new-state multiplier)
                1,              // crashQuota
                500,            // traceEventBudget
                time,             // maxDurationMs (unlimited)
                "localhost:2023",
                true,           // guided (energy-based mutation)
                700,            // maxQueueSize
                0             // reseedFrequency
        );
        fuzzer.run();
    }
}