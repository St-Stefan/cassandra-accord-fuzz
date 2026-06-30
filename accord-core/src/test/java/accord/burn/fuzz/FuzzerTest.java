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
                0             // reseedFrequency
        );
        fuzzer.run();
    }

    /**
     * Long exploration run. Execute via Gradle CLI to avoid IDE memory pressure:
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.testLongExploration"
     */
    @Test
    public void testLongExploration1() {
        long time = 3* 60 * 60 * 1000;
            Fuzzer fuzzer = new Fuzzer(
                    42L,            // seed
                    7,              // numNodes
                    3,              // operations
                    1,              // concurrency
                    Integer.MAX_VALUE,           // iterations
                    30,              // seedPopulationSize
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

    @Test
    public void testLongExploration2() {
        long time = 3* 60 * 60 * 1000;
        Fuzzer fuzzer = new Fuzzer(
                42L,            // seed
                7,              // numNodes
                3,              // operations
                1,              // concurrency
                Integer.MAX_VALUE,           // iterations
                30,              // seedPopulationSize
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