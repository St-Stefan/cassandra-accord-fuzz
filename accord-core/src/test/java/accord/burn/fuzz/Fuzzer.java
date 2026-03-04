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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private final int numNodes;
    private final int iterations;
    private final int seedPopulationSize;
    private final long baseSeed;
    private final int operations;
    private final int concurrency;

    private final Deque<Trace> workQueue;

    public Fuzzer(long seed, int numNodes, int operations, int concurrency,
                  int iterations, int seedPopulationSize, int mutationsPerTrace, int crashQuota) {
        this.random = new Random(seed);
        this.baseSeed = seed;
        this.numNodes = numNodes;
        this.operations = operations;
        this.concurrency = concurrency;
        this.iterations = iterations;
        this.seedPopulationSize = seedPopulationSize;
        this.mutationsPerTrace = mutationsPerTrace;
        this.crashQuota = crashQuota;
        this.workQueue = new ArrayDeque<>();
    }

    /**
     * Run the fuzzer for the configured number of iterations.
     */
    public void run() {
        logger.info("=== FUZZER START === seed={}, nodes={}, ops={}, seeds={}, iterations={}, mutations/trace={}",
                    baseSeed, numNodes, operations, seedPopulationSize, iterations, mutationsPerTrace);

        // Seed phase: generate initial population with random scheduling
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
            Trace schedule = workQueue.isEmpty() ? null : workQueue.poll();
            String mode = schedule != null ? "REPLAY (" + schedule.size() + " events)" : "RANDOM";
            logger.info("[ITER {}/{}] {} | workQueue={}", i + 1, iterations, mode, workQueue.size());

            // Run with schedule (replay mode) and record the actual execution
            Trace result = runBurnTest(schedule, "iter_" + i);
            if (result == null || result.isEmpty()) {
                logger.warn("[ITER {}/{}] No trace produced", i + 1, iterations);
                continue;
            }

            logger.info("[ITER {}/{}] Result: {} events", i + 1, iterations, result.size());

            // TODO: Check coverage here
            // For now, always consider interesting and mutate
            List<Trace> mutants = mutate(result);
            logger.info("[ITER {}/{}] Generated {} mutants", i + 1, iterations, mutants.size());
            for (int m = 0; m < mutants.size(); m++) {
                saveTrace(mutants.get(m), "iter" + i + "_mutant" + m);
            }
            workQueue.addAll(mutants);
        }

        logger.info("=== FUZZER DONE === workQueue remaining: {}", workQueue.size());
    }

    /**
     * Run a burn test, optionally guided by a schedule.
     * Always records the resulting trace.
     */
    private Trace runBurnTest(Trace schedule, String runId) {
        // When replaying, reuse the original seed so burn() generates the same transactions
        long runSeed = schedule != null ? schedule.header().seed() : baseSeed + random.nextLong();
        logger.info("  [{}] runSeed={}, mode={}", runId, runSeed, schedule == null ? "RECORD" : "REPLAY");

        Range r1 = range(forHash(0, BurnTestBase.HASH_RANGE_START),
                        forHash(0, (BurnTestBase.HASH_RANGE_END + BurnTestBase.HASH_RANGE_START) / 2));
        Range r2 = range(forHash(0, (BurnTestBase.HASH_RANGE_END + BurnTestBase.HASH_RANGE_START) / 2),
                        forHash(0, BurnTestBase.HASH_RANGE_END));
        TopologyFactory topologyFactory = new TopologyFactory(numNodes, r1, r2);

        TraceRecorder recorder = new TraceRecorder(runSeed, numNodes, operations, runId);
        CrashSimulator crashes = new CrashSimulator();
        AtomicReference<GuidedPendingQueue> queueRef = new AtomicReference<>();

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
                        guided = GuidedPendingQueue.forRecording(delegate, recorder, crashes);
                    } else {
                        // Replay mode: guided by schedule, but also records the actual execution
                        guided = GuidedPendingQueue.forReplay(delegate, recorder, schedule, crashes);
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

    /**
     * Swap two racy events within a window. Racy = dependent (per TraceEvent.isDependentWith)
     * but from different sources, so the swap actually changes the receiving node's local order.
     */
    private Trace swapEvents(Trace schedule, List<TraceEvent> events) {
        for (int attempt = 0; attempt < 20; attempt++) {
            int i = random.nextInt(events.size());
            int remaining = events.size() - i - 1;
            if (remaining < 1) continue;
            int j = i + 1 + random.nextInt(Math.min(10, remaining));
            if (j >= events.size()) continue;

            TraceEvent a = events.get(i);
            TraceEvent b = events.get(j);

            if (!(a instanceof TraceEvent.Deliver) || !(b instanceof TraceEvent.Deliver)) continue;

            // Dependent (same dest or causal) + different source = racy
            if (a.isDependentWith(b) && !Objects.equals(a.secondaryNode(), b.secondaryNode())) {
                logger.info("    SWAP (racy) [{}] <-> [{}]: {} <-> {}", i, j, a, b);
                List<TraceEvent> swapped = new ArrayList<>(events);
                swapped.set(i, b);
                swapped.set(j, a);
                return new Trace(schedule.header(), swapped);
            }
        }
        logger.info("    SWAP failed: no racy pair found in 20 attempts");
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

    private void saveTrace(Trace trace, String label) {
        try {
            Path dir = Path.of(System.getProperty("user.dir"), "build", "test-traces", "fuzzer");
            Files.createDirectories(dir);
            Path file = dir.resolve(label + ".trace.txt");
            Files.writeString(file, trace.toFullString(), StandardCharsets.UTF_8);
            logger.info("  Saved trace to {}", file);
        } catch (IOException e) {
            logger.warn("  Failed to save trace {}: {}", label, e.getMessage());
        }
    }
}
