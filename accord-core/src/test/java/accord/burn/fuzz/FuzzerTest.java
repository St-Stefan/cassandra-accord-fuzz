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

    /**
     * Basic smoke test for the fuzzing loop.
     * TODO: Remove ephemeral writes? Maybe we should fuzz the full flow
     */
    @Test
    public void testBasicFuzzLoop() {
        Fuzzer fuzzer = new Fuzzer(
            42L,    // seed
            5,      // numNodes
            3,      // operations
            3,      // concurrency
            20,      // iterations
            2,      // seedPopulationSize
            2,      // mutationsPerTrace
            0       // crashQuota (no crashes for now)
        );

        fuzzer.run();
    }
}