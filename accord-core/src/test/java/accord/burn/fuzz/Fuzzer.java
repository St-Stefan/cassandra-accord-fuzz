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

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import accord.api.ProtocolModifiers.Toggles;
import accord.burn.BurnTestBase;
import accord.burn.fuzz.trace.GuidedPendingQueue;
import accord.burn.fuzz.trace.Trace;
import accord.burn.fuzz.trace.TraceEvent;
import accord.burn.fuzz.trace.TraceRecorder;
import accord.impl.TopologyFactory;
import accord.impl.basic.PendingQueue;
import accord.impl.basic.InMemoryJournal;
import accord.local.Node;
import accord.primitives.Range;
import accord.utils.DefaultRandom;
import accord.utils.RandomSource;

import static accord.api.ProtocolModifiers.Toggles.SendStableMessages.TO_ALL;
import static accord.impl.PrefixedIntHashKey.forHash;
import static accord.impl.PrefixedIntHashKey.range;

/**
 * Schedule fuzzer
 */
public class Fuzzer {

    private static final Logger logger = LoggerFactory.getLogger(Fuzzer.class);

    private final Random random;
    private final int mutationsPerTrace;
    private final int crashQuota;
    private final int traceEventBudget;
    private final int numNodes;
    private final int iterations;
    private final int seedPopulationSize;
    private final long baseSeed;
    private final int operations;
    private final int concurrency;

    private final long maxDurationMs;
    private final Deque<Trace> workQueue;

    public Fuzzer(long seed, int numNodes, int operations, int concurrency,
                  int iterations, int seedPopulationSize, int mutationsPerTrace, int crashQuota) {
        this(seed, numNodes, operations, concurrency, iterations, seedPopulationSize, mutationsPerTrace, crashQuota, 0, 0);
    }

    public Fuzzer(long seed, int numNodes, int operations, int concurrency,
                  int iterations, int seedPopulationSize, int mutationsPerTrace, int crashQuota,
                  int traceEventBudget) {
        this(seed, numNodes, operations, concurrency, iterations, seedPopulationSize, mutationsPerTrace, crashQuota, traceEventBudget, 0);
    }

    public Fuzzer(long seed, int numNodes, int operations, int concurrency,
                  int iterations, int seedPopulationSize, int mutationsPerTrace, int crashQuota,
                  int traceEventBudget, long maxDurationMs) {
        this.random = new Random(seed);
        this.baseSeed = seed;
        this.numNodes = numNodes;
        this.operations = operations;
        this.concurrency = concurrency;
        this.iterations = iterations;
        this.seedPopulationSize = seedPopulationSize;
        this.mutationsPerTrace = mutationsPerTrace;
        this.crashQuota = crashQuota;
        this.traceEventBudget = traceEventBudget;
        this.maxDurationMs = maxDurationMs;
        this.workQueue = new ArrayDeque<>();
    }

    /**
     * Run the fuzzer for the configured number of iterations (or until maxDurationMs elapses).
     * All output is written to two session files rather than one file per iteration.
     */
    public void run() {
        long startTime = System.currentTimeMillis();
        String sessionId = baseSeed + "_" + startTime;
        logger.info("=== FUZZER START === seed={}, nodes={}, ops={}, seeds={}, iterations={}, mutations/trace={}, traceBudget={}, maxDuration={}",
                    baseSeed, numNodes, operations, seedPopulationSize, iterations, mutationsPerTrace,
                    traceEventBudget > 0 ? traceEventBudget : "unlimited",
                    maxDurationMs > 0 ? maxDurationMs + "ms" : "unlimited");

        Path dir = Path.of(System.getProperty("user.dir"), "build", "test-traces", "fuzzer");
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new RuntimeException("Cannot create trace output directory", e);
        }

        Path traceFile = dir.resolve("session_" + sessionId + ".trace.txt");
        Path jsonlFile = dir.resolve("session_" + sessionId + ".tla.jsonl");
        Path jsonFile  = dir.resolve("session_" + sessionId + ".tla.json");

        try (BufferedWriter traceWriter = Files.newBufferedWriter(traceFile, StandardCharsets.UTF_8);
             BufferedWriter jsonlWriter = Files.newBufferedWriter(jsonlFile, StandardCharsets.UTF_8);
             BufferedWriter jsonWriter  = Files.newBufferedWriter(jsonFile,  StandardCharsets.UTF_8)) {

            // Seed phase
            for (int i = 0; i < seedPopulationSize; i++) {
                logger.info("[SEED {}/{}] Recording random execution...", i + 1, seedPopulationSize);
                Trace result = runBurnTest(null, "seed_" + i);
                if (result != null && !result.isEmpty()) {
                    logger.info("[SEED {}/{}] Recorded {} events", i + 1, seedPopulationSize, result.size());
                    workQueue.add(result);
                } else {
                    logger.warn("[SEED {}/{}] No trace produced", i + 1, seedPopulationSize);
                }
            }

            // Main fuzzing loop
            for (int i = 0; i < iterations; i++) {
                if (maxDurationMs > 0 && System.currentTimeMillis() - startTime >= maxDurationMs) {
                    logger.info("=== FUZZER TIME LIMIT REACHED after {} iterations ===", i);
                    break;
                }

                Trace schedule = workQueue.isEmpty() ? null : workQueue.poll();
                String mode = schedule != null ? "REPLAY (" + schedule.size() + " events)" : "RANDOM";
                logger.info("[ITER {}/{}] {} | workQueue={}", i + 1, iterations, mode, workQueue.size());

                Trace result = runBurnTest(schedule, "iter_" + i);
                if (result == null || result.isEmpty()) {
                    logger.warn("[ITER {}/{}] No trace produced", i + 1, iterations);
                    continue;
                }

                logger.info("[ITER {}/{}] Result: {} events", i + 1, iterations, result.size());
                saveTrace(result, "iter" + i + "_execution", traceWriter, jsonlWriter, jsonWriter);

                List<Trace> mutants = mutate(result);
                logger.info("[ITER {}/{}] Generated {} mutants", i + 1, iterations, mutants.size());
                workQueue.addAll(mutants);
            }

        } catch (IOException e) {
            logger.error("Session file I/O error: {}", e.getMessage(), e);
        }

        logger.info("=== FUZZER DONE === workQueue remaining: {} | trace: {} | jsonl: {} | json: {}",
                    workQueue.size(), traceFile, jsonlFile, jsonFile);
    }

    /**
     * Run a burn test, optionally guided by a schedule.
     * Always records the resulting trace.
     */
    private Trace runBurnTest(Trace schedule, String runId) {
        // When replaying, reuse the original seed so burn() generates the same transactions
        long runSeed = schedule != null ? schedule.header().seed() : baseSeed + random.nextLong();
        logger.info("  [{}] runSeed={}, mode={}", runId, runSeed, schedule == null ? "RECORD" : "REPLAY");

        Range full = range(forHash(0, BurnTestBase.HASH_RANGE_START),
                forHash(0, BurnTestBase.HASH_RANGE_END));
        TopologyFactory topologyFactory = new TopologyFactory(numNodes, full);

        TraceRecorder recorder = new TraceRecorder(runSeed, numNodes, operations, runId, traceEventBudget);
        CrashSimulator crashes = new CrashSimulator();
        AtomicReference<GuidedPendingQueue> queueRef = new AtomicReference<>();

        Toggles.setSendStableMessages(TO_ALL);
        Toggles.setPermitLocalExecution(false);
        try {
            BurnTestBase.burn(
                new DefaultRandom(runSeed),
                topologyFactory,
                defaultClients(),
                defaultNodes(numNodes),
                10, // keys
                1,  // prefixes
                operations,
                concurrency,
                (RandomSource rnd) -> {
                    PendingQueue delegate = new NoDelayQueue(rnd);
                    GuidedPendingQueue guided;
                    if (schedule == null) {
                        guided = GuidedPendingQueue.forRecording(delegate, recorder, crashes, traceEventBudget > 0 ? traceEventBudget : null);
                    } else {
                        // Replay mode: guided by schedule, but also records the actual execution
                        guided = GuidedPendingQueue.forReplay(delegate, recorder, schedule, crashes, traceEventBudget > 0 ? traceEventBudget : null);
                    }
                    queueRef.set(guided);
                    return guided;
                },
                InMemoryJournal::new
            );
        } catch (Exception e) {
            logger.error("  [{}] Burn test failed: {}", runId, e.getMessage(), e);
            return null;
        }

        return recorder.trace();
    }

    public List<Trace> mutate(Trace schedule) {
        List<Trace> mutants = new ArrayList<>();
        for (int i = 0; i < mutationsPerTrace; i++) {
            Trace mutant = applyRandomMutation(schedule);
            if (mutant != null) {
                mutants.add(mutant);
            }
        }
        logger.info("  Mutated {}/{} (from {} events)", mutants.size(), mutationsPerTrace, schedule.size());
        return mutants;
    }

    private Trace applyRandomMutation(Trace schedule) {
        List<TraceEvent> events = new ArrayList<>(schedule.events());
        if (events.size() < 2) {
            logger.info("    Mutation skipped: trace too small ({} events)", events.size());
            return null;
        }

        int mutationType = random.nextInt(3);
        String[] names = {"SWAP", "CRASH", "RESTART"};
        logger.info("    Attempting mutation: {}", names[mutationType]);
        switch (mutationType) {
            case 0:
                return swapEvents(schedule, events);
            case 1:
                return swapEvents(schedule, events);
            case 2:
                return swapEvents(schedule, events);
            default:
                return null;
        }
    }

    private static final Node.Id CLIENT_NODE = new Node.Id(-1);

    /**
     * Swap two random events as long as we still have one command
     */
    private Trace swapEvents(Trace schedule, List<TraceEvent> events) {
        for (int attempt = 0; attempt < 20; attempt++) {
            int i = random.nextInt(events.size());
            int j = random.nextInt(events.size());
            if (i == j) continue;

            // Ensure i < j for consistent logging
            if (i > j) { int tmp = i; i = j; j = tmp; }

            TraceEvent a = events.get(i);
            TraceEvent b = events.get(j);

            // If swapping into index 0, the replacement must originate from client node -1
            if (i == 0 && !CLIENT_NODE.equals(b.secondaryNode())) continue;

            logger.info("    SWAP [{}] <-> [{}]: {} <-> {}", i, j, a, b);
            List<TraceEvent> swapped = new ArrayList<>(events);
            swapped.set(i, b);
            swapped.set(j, a);
            return new Trace(schedule.header(), swapped);
        }
        logger.info("    SWAP failed: no valid pair found in 20 attempts");
        return null;
    }

    private Trace insertCrash(Trace schedule, List<TraceEvent> events) {
        long existingCrashes = events.stream()
            .filter(e -> e.getEventType() == TraceEvent.TraceEventType.CRASH)
            .count();
        if (existingCrashes >= crashQuota) {
            logger.info("    CRASH skipped: quota reached ({}/{})", existingCrashes, crashQuota);
            return null;
        }

        int position = random.nextInt(events.size());
        Node.Id node = new Node.Id(1 + random.nextInt(numNodes));
        long eventId = events.stream().mapToLong(e -> e.eventId).max().orElse(0) + 1;
        long timestamp = events.get(position).timestamp;

        TraceEvent.Crash crash = new TraceEvent.Crash(eventId, timestamp, node);
        events.add(position, crash);
        logger.info("    CRASH node={} at position {}/{}", node, position, events.size());
        return new Trace(schedule.header(), events);
    }

    private Trace insertRestart(Trace schedule, List<TraceEvent> events) {
        int position = random.nextInt(events.size());
        Node.Id node = new Node.Id(1 + random.nextInt(numNodes));
        long eventId = events.stream().mapToLong(e -> e.eventId).max().orElse(0) + 1;
        long timestamp = events.get(position).timestamp;

        TraceEvent.Recover restart = new TraceEvent.Recover(eventId, timestamp, node);
        events.add(position, restart);
        logger.info("    RESTART node={} at position {}/{}", node, position, events.size());
        return new Trace(schedule.header(), events);
    }

    private static List<Node.Id> defaultClients() {
        return List.of(new Node.Id(-1));
    }

    private static List<Node.Id> defaultNodes(int count) {
        List<Node.Id> nodes = new ArrayList<>(count);
        for (int i = 1; i <= count; i++) {
            nodes.add(new Node.Id(i));
        }
        return nodes;
    }

    private void saveTrace(Trace trace, String label, BufferedWriter traceWriter, BufferedWriter jsonlWriter, BufferedWriter jsonWriter) {
        try {
            traceWriter.write("=== " + label + " ===\n");
            traceWriter.write(trace.toFullString());
            traceWriter.write("\n\n");
            traceWriter.flush();

            jsonlWriter.write(trace.toTlaJson(false));
            jsonlWriter.flush();

            jsonWriter.write(trace.toTlaJson(true));
            jsonWriter.write('\n');
            jsonWriter.flush();
        } catch (IOException e) {
            logger.warn("  Failed to append trace {}: {}", label, e.getMessage());
        }
    }
}
