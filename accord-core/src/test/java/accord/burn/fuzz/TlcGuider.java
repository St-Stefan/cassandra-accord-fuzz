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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import accord.burn.fuzz.trace.Trace;

public class TlcGuider {

    private static final Logger logger = LoggerFactory.getLogger(TlcGuider.class);

    // State blocks starting with these prefixes are excluded from the abstract key,
    // matching the abstraction in trace_tlc_abstract.py (msgs and timestamps ignored).
    private static final String[] EXCLUDED_PREFIXES = { "/\\ msgs", "/\\ ts" };

    private final TlcClient client;
    private final Set<String> seenStates = new HashSet<>();

    public TlcGuider(String addr) {
        this.client = new TlcClient(addr);
    }

    /**
     * Send trace to TLC and return the number of newly discovered abstract states.
     * Returns 0 on contact failure so the fuzzer degrades gracefully.
     */
    public int check(Trace trace) {
        TlcClient.TlcResult result;
        try {
            result = client.execute(trace);
        } catch (IOException e) {
            logger.warn("TLC contact failed (skipping guidance): {}", e.getMessage());
            return 0;
        }
        int newCount = 0;
        for (String state : result.states())
            if (seenStates.add(abstractKey(state))) newCount++;
        return newCount;
    }

    public int totalSeenStates() {
        return seenStates.size();
    }

    /**
     * Compute an abstract state key by filtering out excluded variable blocks
     * (msgs, ts) and MD5-hashing the remainder — same logic as trace_tlc_abstract.py.
     */
    private static String abstractKey(String stateStr) {
        // TLC state strings use /\ as the conjunction operator at the start of each variable block.
        // Split on newline-before-/\ to get one block per variable.
        String[] blocks = stateStr.split("\n(?=/\\\\)");
        StringBuilder sb = new StringBuilder();
        for (String block : blocks) {
            boolean excluded = false;
            for (String prefix : EXCLUDED_PREFIXES)
                if (block.startsWith(prefix)) { excluded = true; break; }
            if (!excluded)
                sb.append(block).append('\n');
        }
        try {
            byte[] digest = MessageDigest.getInstance("MD5")
                                         .digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(32);
            for (byte b : digest)
                hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 unavailable", e); // can't happen on any compliant JVM
        }
    }
}