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

package accord.burn;

import java.io.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicReference;

import accord.burn.fuzz.NoDelayQueue;
import org.junit.jupiter.api.Test;

import accord.burn.fuzz.CrashSimulator;
import accord.burn.fuzz.trace.GuidedPendingQueue;
import accord.burn.fuzz.trace.Trace;
import accord.burn.fuzz.trace.TraceEvent;
import accord.burn.fuzz.trace.TraceRecorder;
import accord.impl.TopologyFactory;
import accord.impl.basic.PendingQueue;
import accord.impl.basic.RandomDelayQueue;
import accord.impl.basic.InMemoryJournal;
import accord.local.Node;
import accord.primitives.Range;
import accord.utils.DefaultRandom;
import accord.utils.RandomSource;

import static accord.impl.PrefixedIntHashKey.forHash;
import static accord.impl.PrefixedIntHashKey.range;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for GuidedPendingQueue trace recording.
 * For now, this test verifies that recording works correctly.
 */
public class GuidedPendingQueueRecordReplayTest extends BurnTestBase {
    @Test
    public void recordThenReplay() throws IOException {
        // 3 sets of 3 concurrent requests
        long seed = 123456799L;
        int nodeCount = 5;
        int operations = 3;
        int concurrency = 2;

        Range r1 = range(forHash(0, HASH_RANGE_START), forHash(0, (HASH_RANGE_END + HASH_RANGE_START) / 2));
        Range r2 = range(forHash(0, (HASH_RANGE_END + HASH_RANGE_START) / 2), forHash(0, HASH_RANGE_END));
        // Replication factor across 5 nodes; use rf=5 so every node belongs to each shard electorate
        TopologyFactory topologyFactory = new TopologyFactory(nodeCount, r1, r2);

        // Record
        AtomicReference<GuidedPendingQueue> recordedQueueRef = new AtomicReference<>();
        TraceRecorder recorder = new TraceRecorder(seed, nodeCount, operations, "guided-record-replay");
        CrashSimulator crashes = new CrashSimulator();

        BurnTestBase.burn(new DefaultRandom(seed), topologyFactory, defaultClients(), defaultNodes(nodeCount), 10, 1, operations, concurrency,
                (RandomSource rnd) -> {
                    PendingQueue delegate = new NoDelayQueue(rnd);
                    GuidedPendingQueue guided = GuidedPendingQueue.forRecording(delegate, recorder, crashes);
                    recordedQueueRef.set(guided);
                    return guided;
                },
                InMemoryJournal::new);

        GuidedPendingQueue recordedQueue = recordedQueueRef.get();
        assertNotNull(recordedQueue, "recorded guided queue");

        Trace recordedTrace = recorder.trace();
        assertNotNull(recordedTrace, "recorded trace");
        assertFalse(recordedTrace.isEmpty(), "expected some trace events to be recorded");

        // Log trace statistics
        System.out.println("Recorded trace with " + recordedTrace.size() + " events");
        System.out.println("Delivers: " + recordedTrace.countByKind(TraceEvent.TraceEventType.DELIVER));
        System.out.println("Drops: " + recordedTrace.countByKind(TraceEvent.TraceEventType.DROP));

        // Verify we recorded meaningful events
        assertTrue(recordedTrace.countByKind(TraceEvent.TraceEventType.DELIVER) > 0,
                "expected at least some DELIVER events");

        // Persist trace to a file for debugging / future replay tooling
        writeTraceToFile(recordedTrace, seed, nodeCount, operations);
    }

    @Test
    public void replayRecordedTrace() throws IOException {
        long seed = 123456799L;
        int nodeCount = 5;
        int operations = 3;
        int concurrency = 3;

        Range r1 = range(forHash(0, HASH_RANGE_START), forHash(0, (HASH_RANGE_END + HASH_RANGE_START) / 2));
        Range r2 = range(forHash(0, (HASH_RANGE_END + HASH_RANGE_START) / 2), forHash(0, HASH_RANGE_END));
        TopologyFactory topologyFactory = new TopologyFactory(nodeCount, r1, r2);
        // === RECORD PHASE ===
        AtomicReference<GuidedPendingQueue> recordedQueueRef = new AtomicReference<>();
        TraceRecorder recorder = new TraceRecorder(seed, nodeCount, operations, "replay-test-record");
        CrashSimulator crashes = new CrashSimulator();
        System.out.println("=== STARTING BURN === " + topologyFactory);
        BurnTestBase.burn(new DefaultRandom(seed), topologyFactory, defaultClients(), defaultNodes(nodeCount), 10, 1, operations, concurrency,
                (RandomSource rnd) -> {
                    PendingQueue delegate = new NoDelayQueue(rnd);
                    GuidedPendingQueue guided = GuidedPendingQueue.forRecording(delegate, recorder, crashes);
                    recordedQueueRef.set(guided);
                    return guided;
                },
                InMemoryJournal::new);

        Trace recordedTrace = recorder.trace();
        assertNotNull(recordedTrace, "recorded trace");
        assertFalse(recordedTrace.isEmpty(), "expected trace events");

        System.out.println("=== RECORD PHASE COMPLETE ===");
        System.out.println("Recorded " + recordedTrace.size() + " events");
        System.out.println("Delivers: " + recordedTrace.countByKind(TraceEvent.TraceEventType.DELIVER));
        System.out.println("Drops: " + recordedTrace.countByKind(TraceEvent.TraceEventType.DROP));

        // Print first 20 events for debugging
        System.out.println("\nFirst 20 recorded events:");
        for (int i = 0; i < Math.min(20, recordedTrace.size()); i++) {
            System.out.println("  " + i + ": " + recordedTrace.get(i));
        }

        // === REPLAY PHASE ===
        System.out.println("\n=== REPLAY PHASE ===");
        AtomicReference<GuidedPendingQueue> replayQueueRef = new AtomicReference<>();
        TraceRecorder replayRecorder = new TraceRecorder(seed, nodeCount, operations, "replay-test-replay");
        CrashSimulator replayCrashes = new CrashSimulator();

        BurnTestBase.burn(new DefaultRandom(seed), topologyFactory, defaultClients(), defaultNodes(nodeCount), 10, 1, operations, concurrency,
                (RandomSource rnd) -> {
                    PendingQueue delegate = new NoDelayQueue(rnd);
                    GuidedPendingQueue guided = GuidedPendingQueue.forReplay(delegate, replayRecorder, recordedTrace, replayCrashes);
                    replayQueueRef.set(guided);
                    return guided;
                },
                InMemoryJournal::new);

        GuidedPendingQueue replayQueue = replayQueueRef.get();
        Trace replayedTrace = replayRecorder.trace();

        System.out.println("=== REPLAY PHASE COMPLETE ===");
        System.out.println("Replayed " + replayedTrace.size() + " events");
        System.out.println("Replay complete: " + replayQueue.isReplayComplete());

        // Print first 20 replay events for comparison
        System.out.println("\nFirst 20 replayed events:");
        for (int i = 0; i < Math.min(20, replayedTrace.size()); i++) {
            System.out.println("  " + i + ": " + replayedTrace.get(i));
        }

        // Basic sanity checks
        assertTrue(replayedTrace.size() > 0, "replay should produce events");
    }

    private static void writeTraceToFile(Trace trace, long seed, int nodeCount, int operations) throws IOException {
        String workDir = System.getProperty("user.dir");
        Path outDir = Path.of(workDir, "build", "test-traces");
        Files.createDirectories(outDir);

        Path outFile = outDir.resolve(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) + "trace.txt");
        Files.writeString(outFile, trace.toFullString(), StandardCharsets.UTF_8);
        System.out.println("Trace written to: " + outFile.toAbsolutePath());
    }

    private static java.util.List<Node.Id> defaultClients() {
        // BurnTestBase conventions use negative ids for clients
        return java.util.List.of(new Node.Id(-1));
    }

    private static java.util.List<Node.Id> defaultNodes(int count) {
        java.util.ArrayList<Node.Id> out = new java.util.ArrayList<>(count);
        for (int i = 1; i <= count; i++) out.add(new Node.Id(i));
        return out;
    }
}
