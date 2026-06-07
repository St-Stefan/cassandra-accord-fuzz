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
                0,      // crashQuota
                300     // traceEventBudget
        );
        fuzzer.run();
    }

    /**
     * Long exploration run. Execute via Gradle CLI to avoid IDE memory pressure:
     *   ./gradlew :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.testLongExploration"
     */
    @Test
    public void testLongExploration() {
        long time = 60 * 60 * 1000;
        Fuzzer fuzzer = new Fuzzer(
                42L,            // seed
                7,              // numNodes
                3,              // operations
                3,              // concurrency
                Integer.MAX_VALUE, // iterations (time-bounded instead)
                1,              // seedPopulationSize
                1,              // mutationsPerTrace
                0,              // crashQuota
                300,            // traceEventBudget
                time       // maxDurationMs
        );
        fuzzer.run();
    }
}