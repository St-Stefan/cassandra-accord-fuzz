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

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Shared filename builder for every fuzzer/replay output. Timestamp comes first so a directory
 * listing sorts chronologically across runs regardless of mode/nodes/seed; the rest identifies
 * the run without needing to open the file.
 */
public final class SessionNaming
{
    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss");

    private SessionNaming() {}

    public static String id(String label, int numNodes, long seed)
    {
        return LocalDateTime.now().format(TIMESTAMP) + "_" + label + "_n" + numNodes + "_seed" + seed;
    }
}