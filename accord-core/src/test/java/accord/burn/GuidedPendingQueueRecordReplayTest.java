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

import java.util.List;

import accord.api.ProtocolModifiers.Toggles;
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

import static accord.api.ProtocolModifiers.Toggles.SendStableMessages.TO_ALL;
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
        long seed = 42L;
        int nodeCount = 5;
        int operations = 3;
        int concurrency = 1;

        Range r1 = range(forHash(0, HASH_RANGE_START), forHash(0, (HASH_RANGE_END + HASH_RANGE_START) / 2));
        Range r2 = range(forHash(0, (HASH_RANGE_END + HASH_RANGE_START) / 2), forHash(0, HASH_RANGE_END));
        TopologyFactory topologyFactory = new TopologyFactory(nodeCount, r1, r2);

        // Record
        AtomicReference<GuidedPendingQueue> recordedQueueRef = new AtomicReference<>();
        TraceRecorder recorder = new TraceRecorder(seed, nodeCount, operations, "guided-record-replay");
        CrashSimulator crashes = new CrashSimulator();

        BurnTestBase.burn(new DefaultRandom(seed), topologyFactory, defaultClients(), defaultNodes(nodeCount), 2, 1, operations, concurrency,
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
        long seed = 42;
        int nodeCount = 7;
        int operations = 3;
        int concurrency = 1;

        Range r1 = range(forHash(0, HASH_RANGE_START), forHash(0, (HASH_RANGE_END + HASH_RANGE_START) / 2));
        Range r2 = range(forHash(0, (HASH_RANGE_END + HASH_RANGE_START) / 2), forHash(0, HASH_RANGE_END));
        TopologyFactory topologyFactory = new TopologyFactory(nodeCount, r1, r2);
        // === RECORD PHASE ===
        AtomicReference<GuidedPendingQueue> recordedQueueRef = new AtomicReference<>();
        TraceRecorder recorder = new TraceRecorder(seed, nodeCount, operations, "replay-test-record");
        CrashSimulator crashes = new CrashSimulator();
        System.out.println("=== STARTING BURN === " + topologyFactory);
        BurnTestBase.burn(new DefaultRandom(seed), topologyFactory, defaultClients(), defaultNodes(nodeCount), 2, 1, operations, concurrency,
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

    /**
     * Reproducer for the bug found at fuzzer iteration 58372.
     *
     * Seed -7610621359446545149 (iter_58348), SWAP [9]<->[11]:
     * coordinator node 2 crashes, sends PreAccepts to nodes 6 and 1,
     * then node 2 recovers mid-fanout (before PreAccept reaches nodes 4 and 3).
     * This triggers an invariant violation in Command.validate() during Accept.
     */
    @Test
    public void replayBugIter58372() {
        long seed = -7610621359446545149L;
        int nodeCount = 7;
        int operations = 3;
        int concurrency = 1;

        Range full = range(forHash(0, HASH_RANGE_START), forHash(0, HASH_RANGE_END));
        TopologyFactory topologyFactory = new TopologyFactory(nodeCount, full);

        Trace schedule = buildFailingSchedule(seed, nodeCount, operations);

        Toggles.setSendStableMessages(TO_ALL);
        Toggles.setPermitLocalExecution(false);
        BurnTestBase.allowEphemeralReads = false;
        BurnTestBase.coordinatorNodes = List.of(new Node.Id(1), new Node.Id(2), new Node.Id(3));

        AtomicReference<GuidedPendingQueue> queueRef = new AtomicReference<>();
        TraceRecorder recorder = new TraceRecorder(seed, nodeCount, operations, "bug-iter58372");
        CrashSimulator crashes = new CrashSimulator();

        BurnTestBase.burn(new DefaultRandom(seed), topologyFactory,
                List.of(new Node.Id(-1)), defaultNodes(nodeCount),
                2, 1, operations, concurrency,
                (RandomSource rnd) -> {
                    PendingQueue delegate = new NoDelayQueue(rnd);
                    GuidedPendingQueue guided = GuidedPendingQueue.forReplay(delegate, recorder, schedule, crashes);
                    queueRef.set(guided);
                    return guided;
                },
                InMemoryJournal::new,
                crashes);
    }

    /**
     * The failing schedule: iter_58348 with SWAP [9]<->[11].
     *
     * Original [9]: PreAccept from node 2 to node 4
     * Original [11]: Recover node 2
     *
     * After swap, node 2 recovers before its PreAccept reaches node 4 (and node 3).
     */
    private static Trace buildFailingSchedule(long seed, int nodeCount, int operations) {
        Trace.Header header = new Trace.Header(seed, nodeCount, operations, "bug-iter58372-repro");
        Trace trace = new Trace(header);

        Node.Id client = new Node.Id(-1);
        Node.Id n1 = new Node.Id(1);
        Node.Id n2 = new Node.Id(2);
        Node.Id n3 = new Node.Id(3);
        Node.Id n4 = new Node.Id(4);
        Node.Id n5 = new Node.Id(5);
        Node.Id n6 = new Node.Id(6);
        Node.Id n7 = new Node.Id(7);

        // Helper: a Deliver event matched only by from/to (other fields unused by replay)
        // event 0: client submits to coordinator node 2
        trace.add(deliver(0, client, n2));
        // events 1-4: recoveries before coordinator sends anything
        trace.add(recover(1, n7));
        trace.add(recover(2, n4));
        trace.add(recover(3, n4));
        trace.add(recover(4, n7));
        // event 5: coordinator node 2 crashes
        trace.add(crash(5, n2));
        // event 6: recovery of node 3
        trace.add(recover(6, n3));
        // events 7-8: PreAccept reaches nodes 6 and 1 before the swap point
        trace.add(deliver(7, n2, n6));
        trace.add(deliver(8, n2, n1));
        // event 9: Recover node 2 (swapped from position 11) — mid-fanout recovery
        trace.add(recover(9, n2));
        // event 10: PreAccept to node 5
        trace.add(deliver(10, n2, n5));
        // event 11: PreAccept to node 4 (swapped from position 9)
        trace.add(deliver(11, n2, n4));
        // event 12: PreAccept to node 3
        trace.add(deliver(12, n2, n3));

        return trace;
    }

    private static TraceEvent deliver(long id, Node.Id from, Node.Id to) {
        return new TraceEvent.Deliver(id, 0, id, from, to, null, null, "PreAccept",
                Long.MIN_VALUE, Long.MIN_VALUE, 0);
    }

    private static TraceEvent crash(long id, Node.Id node) {
        return new TraceEvent.Crash(id, 0, node);
    }

    private static TraceEvent recover(long id, Node.Id node) {
        return new TraceEvent.Recover(id, 0, node);
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
