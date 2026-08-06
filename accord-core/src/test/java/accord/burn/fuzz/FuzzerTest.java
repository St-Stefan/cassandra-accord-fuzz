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

    // --- 24h matrix runs -------------------------------------------------------------------
    // Node count comes from the "fuzz.nodes" system property (set via -PfuzzNodes on the Gradle
    // command line - see accord-core/build.gradle) so the same method drives 5/7/9-node runs
    // without editing source. Each method loops one 5-seed set internally, one 24h Fuzzer run per
    // seed, so one Gradle invocation covers half a (mode, node count) row of the matrix. Which
    // set runs comes from the "fuzz.seedSet" system property (set via -PfuzzSet; 1 or 2, defaults
    // to 1 if unset) so both halves can run as separate parallel processes.
    // Requires a TLC server at localhost:2023 for modelfuzzMatrix/predicateMatrix's TLC-comparison
    // column; both degrade gracefully (coverage.csv stays at 0) if it isn't reachable.

    private static final long[] SEED_SET_1 = {1L, 2L, 42L, 420L, 5L};
    private static final long[] SEED_SET_2 = {6L, 123L, 8L, 9L, 10L};
    private static final long MATRIX_RUN_DURATION_MS = 24L * 60 * 60 * 1000;

    private static int matrixNumNodes() {
        return Integer.getInteger("fuzz.nodes", 7);
    }

    private static long[] matrixSeeds() {
        int set = Integer.getInteger("fuzz.seedSet", 1);
        return switch (set) {
            case 1 -> SEED_SET_1;
            case 2 -> SEED_SET_2;
            default -> throw new IllegalArgumentException("fuzz.seedSet must be 1 or 2, was " + set);
        };
    }

    /**
     * TLC/ModelFuzz-guided: mutation energy comes from newly discovered TLC states.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.modelfuzzMatrix" -PfuzzNodes=7 -PfuzzSet=1
     */
    @Test
    public void modelfuzzMatrix() {
        int numNodes = matrixNumNodes();
        for (long seed : matrixSeeds()) {
            new Fuzzer(seed, numNodes, 3, 1,
                       Integer.MAX_VALUE, 40, 1, 1,
                       500, MATRIX_RUN_DURATION_MS, "localhost:2023", true, 700, 0,
                       false, false, HistoryMode.FULL_HISTORY, StageClassifier.EXTENT,
                       "modelfuzz").run();
        }
    }

    /**
     * Unguided: swap/crash/restart mutations applied every iteration regardless of coverage.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.randomMatrix" -PfuzzNodes=7 -PfuzzSet=1
     */
    @Test
    public void randomMatrix() {
        int numNodes = matrixNumNodes();
        for (long seed : matrixSeeds()) {
            new Fuzzer(seed, numNodes, 3, 1,
                       Integer.MAX_VALUE, 40, 1, 1,
                       500, MATRIX_RUN_DURATION_MS, "localhost:2023", false, 700, 0,
                       false, false, HistoryMode.FULL_HISTORY, StageClassifier.EXTENT,
                       "random").run();
        }
    }

    /**
     * Pure random schedule generation each iteration (ModelFuzz-style), no mutation feedback loop.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.randomScheduleMatrix" -PfuzzNodes=7 -PfuzzSet=1
     */
    @Test
    public void randomScheduleMatrix() {
        int numNodes = matrixNumNodes();
        for (long seed : matrixSeeds()) {
            new Fuzzer(seed, numNodes, 3, 1,
                       Integer.MAX_VALUE, 40, 1, 1,
                       500, MATRIX_RUN_DURATION_MS, "localhost:2023", false, 700, 0,
                       true, false, HistoryMode.FULL_HISTORY, StageClassifier.EXTENT,
                       "randomschedule").run();
        }
    }

    /**
     * Predicate-guided: mutation energy comes from {@link accord.burn.fuzz.predicate.PredicateGuider}
     * (full history, EXTENT classifier) - no external dependency.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.predicateMatrix" -PfuzzNodes=7 -PfuzzSet=1
     */
    @Test
    public void predicateMatrix() {
        int numNodes = matrixNumNodes();
        for (long seed : matrixSeeds()) {
            new Fuzzer(seed, numNodes, 3, 1,
                       Integer.MAX_VALUE, 40, 1, 1,
                       500, MATRIX_RUN_DURATION_MS, "localhost:2023", true, 700, 0,
                       false, true, HistoryMode.FULL_HISTORY, StageClassifier.EXTENT,
                       "predicate").run();
        }
    }

    /**
     * Predicate-guided, full history but the coarser REACHED_COMPLETED classifier instead of EXTENT.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.predicateReachedMatrix" -PfuzzNodes=7 -PfuzzSet=1
     */
    @Test
    public void predicateReachedMatrix() {
        int numNodes = matrixNumNodes();
        for (long seed : matrixSeeds()) {
            new Fuzzer(seed, numNodes, 3, 1,
                       Integer.MAX_VALUE, 40, 1, 1,
                       500, MATRIX_RUN_DURATION_MS, "localhost:2023", true, 700, 0,
                       false, true, HistoryMode.FULL_HISTORY, StageClassifier.REACHED_COMPLETED,
                       "predicateReached").run();
        }
    }

    /**
     * Predicate-guided, CURRENT_STAGE_ONLY (compressed) history with the EXTENT classifier, and
     * periodic reseeding every 7000 iterations instead of the other variants' pure mutation queue.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.predicateCompressedMatrix" -PfuzzNodes=7 -PfuzzSet=1
     */
    @Test
    public void predicateCompressedMatrix() {
        int numNodes = matrixNumNodes();
        for (long seed : matrixSeeds()) {
            new Fuzzer(seed, numNodes, 3, 1,
                       Integer.MAX_VALUE, 40, 1, 1,
                       500, MATRIX_RUN_DURATION_MS, "localhost:2023", true, 700, 7000,
                       false, true, HistoryMode.CURRENT_STAGE_ONLY, StageClassifier.EXTENT,
                       "predicateCompressed").run();
        }
    }

    /**
     * Predicate-guided, full history but the coarser REACHED_COMPLETED classifier instead of EXTENT.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.predicateReachedMatrix" -PfuzzNodes=7 -PfuzzSet=1
     */
    @Test
    public void predicateReachedMatrix() {
        int numNodes = matrixNumNodes();
        for (long seed : matrixSeeds()) {
            new Fuzzer(seed, numNodes, 3, 1,
                       Integer.MAX_VALUE, 40, 1, 1,
                       500, MATRIX_RUN_DURATION_MS, "localhost:2023", true, 700, 0,
                       false, true, HistoryMode.FULL_HISTORY, StageClassifier.REACHED_COMPLETED,
                       "predicateReached").run();
        }
    }

    /**
     * Predicate-guided, CURRENT_STAGE_ONLY (compressed) history with the EXTENT classifier, and
     * periodic reseeding every 7000 iterations instead of the other variants' pure mutation queue.
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.predicateCompressedMatrix" -PfuzzNodes=7 -PfuzzSet=1
     */
    @Test
    public void predicateCompressedMatrix() {
        int numNodes = matrixNumNodes();
        for (long seed : matrixSeeds()) {
            new Fuzzer(seed, numNodes, 3, 1,
                       Integer.MAX_VALUE, 40, 1, 1,
                       500, MATRIX_RUN_DURATION_MS, "localhost:2023", true, 700, 7000,
                       false, true, HistoryMode.CURRENT_STAGE_ONLY, StageClassifier.EXTENT,
                       "predicateCompressed").run();
        }
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