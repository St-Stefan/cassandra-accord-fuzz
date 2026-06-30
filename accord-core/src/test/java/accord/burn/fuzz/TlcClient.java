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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import accord.burn.fuzz.trace.Trace;

public class TlcClient {

    public record TlcResult(long[] keys, String[] states) {}

    private final String baseUrl;
    private final HttpClient http;

    public TlcClient(String addr) {
        this.baseUrl = "http://" + addr;
        this.http = HttpClient.newBuilder()
                              .connectTimeout(Duration.ofSeconds(5))
                              .build();
    }

    /** POST the trace to /execute, return TLC state fingerprints and string representations. */
    public TlcResult execute(Trace trace) throws IOException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/execute"))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(trace.toTlaJson(true)))
                .build();
        try {
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200)
                throw new IOException("TLC returned HTTP " + resp.statusCode() + ": " + resp.body());
            String body = resp.body();
            return new TlcResult(parseKeys(body), parseStates(body));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted waiting for TLC", e);
        }
    }

    /** Extract the Keys array from {"States":[...],"Keys":[n1,n2,...]}. */
    private static long[] parseKeys(String json) {
        int idx = json.indexOf("\"Keys\"");
        if (idx < 0) idx = json.indexOf("\"keys\"");
        if (idx < 0) return new long[0];
        int start = json.indexOf('[', idx) + 1;
        int end   = json.indexOf(']', start);
        if (start <= 0 || end < 0) return new long[0];
        String inner = json.substring(start, end).trim();
        if (inner.isEmpty()) return new long[0];
        String[] parts = inner.split(",");
        long[] keys = new long[parts.length];
        for (int i = 0; i < parts.length; i++)
            keys[i] = Long.parseLong(parts[i].trim());
        return keys;
    }

    /** Extract the States string array, unescaping JSON string sequences. */
    private static String[] parseStates(String json) {
        int idx = json.indexOf("\"States\"");
        if (idx < 0) idx = json.indexOf("\"states\"");
        if (idx < 0) return new String[0];
        int arrStart = json.indexOf('[', idx);
        if (arrStart < 0) return new String[0];

        List<String> result = new ArrayList<>();
        int i = arrStart + 1;
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == ']') break;
            if (c == '"') {
                i++;
                StringBuilder sb = new StringBuilder();
                while (i < json.length()) {
                    c = json.charAt(i++);
                    if (c == '"') break;
                    if (c == '\\' && i < json.length()) {
                        char esc = json.charAt(i++);
                        switch (esc) {
                            case 'n'  -> sb.append('\n');
                            case 't'  -> sb.append('\t');
                            case 'r'  -> sb.append('\r');
                            case '"'  -> sb.append('"');
                            case '\\' -> sb.append('\\');
                            default   -> { sb.append('\\'); sb.append(esc); }
                        }
                    } else {
                        sb.append(c);
                    }
                }
                result.add(sb.toString());
            } else {
                i++;
            }
        }
        return result.toArray(new String[0]);
    }
}