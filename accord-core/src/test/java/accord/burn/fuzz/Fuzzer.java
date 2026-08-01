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
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import accord.api.ProtocolModifiers.Toggles;
import accord.burn.BurnTestBase;
import accord.burn.fuzz.predicate.HistoryMode;
import accord.burn.fuzz.predicate.PredicateGuider;
import accord.burn.fuzz.predicate.StageClassifier;
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
    private final TlcGuider guider;
    // Predicate-based coverage has no external dependency (unlike TlcGuider/TLC server), so it is
    // always constructed and always checked every iteration - purely for measurement/comparison
    // unless usePredicateGuidance selects it to drive mutation energy instead of TLC.
    private final PredicateGuider predicateGuider;
    private final boolean usePredicateGuidance;
    private final boolean guided;
    private final int maxQueueSize;
    private final int reseedFrequency;
    private final boolean randomSchedule;

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
        this(seed, numNodes, operations, concurrency, iterations, seedPopulationSize,
             mutationsPerTrace, crashQuota, traceEventBudget, maxDurationMs, null, false, Integer.MAX_VALUE, 0);
    }

    public Fuzzer(long seed, int numNodes, int operations, int concurrency,
                  int iterations, int seedPopulationSize, int mutationsPerTrace, int crashQuota,
                  int traceEventBudget, long maxDurationMs, String tlcAddr, boolean guided, int maxQueueSize, int reseedFrequency) {
        this(seed, numNodes, operations, concurrency, iterations, seedPopulationSize, mutationsPerTrace, crashQuota,
             traceEventBudget, maxDurationMs, tlcAddr, guided, maxQueueSize, reseedFrequency, false);
    }

    public Fuzzer(long seed, int numNodes, int operations, int concurrency,
                  int iterations, int seedPopulationSize, int mutationsPerTrace, int crashQuota,
                  int traceEventBudget, long maxDurationMs, String tlcAddr, boolean guided, int maxQueueSize, int reseedFrequency,
                  boolean randomSchedule) {
        this(seed, numNodes, operations, concurrency, iterations, seedPopulationSize, mutationsPerTrace, crashQuota,
             traceEventBudget, maxDurationMs, tlcAddr, guided, maxQueueSize, reseedFrequency, randomSchedule, false);
    }

    /**
     * @param usePredicateGuidance if true, mutation energy is driven by {@link PredicateGuider}
     *                             instead of the TLC {@link TlcGuider}; TLC coverage (if tlcAddr
     *                             is set) is still computed and logged every iteration either way,
     *                             purely for measurement/comparison.
     */
    public Fuzzer(long seed, int numNodes, int operations, int concurrency,
                  int iterations, int seedPopulationSize, int mutationsPerTrace, int crashQuota,
                  int traceEventBudget, long maxDurationMs, String tlcAddr, boolean guided, int maxQueueSize, int reseedFrequency,
                  boolean randomSchedule, boolean usePredicateGuidance) {
        this(seed, numNodes, operations, concurrency, iterations, seedPopulationSize, mutationsPerTrace, crashQuota,
             traceEventBudget, maxDurationMs, tlcAddr, guided, maxQueueSize, reseedFrequency, randomSchedule, usePredicateGuidance,
             HistoryMode.FULL_HISTORY);
    }

    /**
     * @param predicateHistoryMode selects how {@link PredicateGuider}'s joint-state key retains a
     *                             transaction's stage history: every stage ever touched ({@link
     *                             HistoryMode#FULL_HISTORY}, the default) or just its current
     *                             backbone stage plus a separate recovery slot ({@link
     *                             HistoryMode#CURRENT_STAGE_ONLY}) - see {@code
     *                             accord.burn.fuzz.predicate.StageSlot}.
     */
    public Fuzzer(long seed, int numNodes, int operations, int concurrency,
                  int iterations, int seedPopulationSize, int mutationsPerTrace, int crashQuota,
                  int traceEventBudget, long maxDurationMs, String tlcAddr, boolean guided, int maxQueueSize, int reseedFrequency,
                  boolean randomSchedule, boolean usePredicateGuidance, HistoryMode predicateHistoryMode) {
        this(seed, numNodes, operations, concurrency, iterations, seedPopulationSize, mutationsPerTrace, crashQuota,
             traceEventBudget, maxDurationMs, tlcAddr, guided, maxQueueSize, reseedFrequency, randomSchedule, usePredicateGuidance,
             predicateHistoryMode, StageClassifier.EXTENT);
    }

    /**
     * @param predicateClassifier selects the {@link StageClassifier} {@link PredicateGuider} uses -
     *                            {@link StageClassifier#EXTENT} (the default) or {@link
     *                            StageClassifier#REACHED_COMPLETED}.
     */
    public Fuzzer(long seed, int numNodes, int operations, int concurrency,
                  int iterations, int seedPopulationSize, int mutationsPerTrace, int crashQuota,
                  int traceEventBudget, long maxDurationMs, String tlcAddr, boolean guided, int maxQueueSize, int reseedFrequency,
                  boolean randomSchedule, boolean usePredicateGuidance, HistoryMode predicateHistoryMode, StageClassifier predicateClassifier) {
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
        this.guider = tlcAddr != null ? new TlcGuider(tlcAddr) : null;
        this.predicateGuider = new PredicateGuider(predicateClassifier, predicateHistoryMode);
        this.usePredicateGuidance = usePredicateGuidance;
        this.guided = guided;
        this.maxQueueSize = maxQueueSize;
        this.reseedFrequency = reseedFrequency;
        this.randomSchedule = randomSchedule;
    }

    /**
     * Run the fuzzer for the configured number of iterations (or until maxDurationMs elapses).
     * All output is written to two session files rather than one file per iteration.
     */
    public void run() {
        long startTime = System.currentTimeMillis();
        String sessionId = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HHmm_ddMM")) + "_seed" + baseSeed;
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

        Path traceFile          = dir.resolve("session_" + sessionId + ".trace.txt");
        Path jsonlFile          = dir.resolve("session_" + sessionId + ".tla.jsonl");
        Path jsonFile           = dir.resolve("session_" + sessionId + ".tla.json");
        Path csvFile            = dir.resolve("session_" + sessionId + ".coverage.csv");
        Path predicateCsvFile   = dir.resolve("session_" + sessionId + ".predicate_coverage.csv");
        Path pendingFile        = dir.resolve("session_" + sessionId + ".pending.txt");
        Path repopulateFile     = dir.resolve("session_" + sessionId + ".repopulate.csv");
        Path errorsFile         = dir.resolve("session_" + sessionId + ".errors.csv");

        try (BufferedWriter traceWriter        = Files.newBufferedWriter(traceFile,        StandardCharsets.UTF_8);
             BufferedWriter jsonlWriter        = Files.newBufferedWriter(jsonlFile,        StandardCharsets.UTF_8);
             BufferedWriter jsonWriter         = Files.newBufferedWriter(jsonFile,         StandardCharsets.UTF_8);
             BufferedWriter csvWriter          = Files.newBufferedWriter(csvFile,          StandardCharsets.UTF_8);
             BufferedWriter predicateCsvWriter = Files.newBufferedWriter(predicateCsvFile, StandardCharsets.UTF_8);
             BufferedWriter pendingWriter      = Files.newBufferedWriter(pendingFile,      StandardCharsets.UTF_8);
             BufferedWriter repopulateWriter   = Files.newBufferedWriter(repopulateFile,   StandardCharsets.UTF_8);
             BufferedWriter errorsWriter       = Files.newBufferedWriter(errorsFile,       StandardCharsets.UTF_8)) {

            if (guider != null)
                csvWriter.write("iteration,unique_abstract_states\n");
            predicateCsvWriter.write("iteration,unique_abstract_states\n");
            repopulateWriter.write("iteration\n");
            errorsWriter.write("run_id,seed,exception_class,full_stack_trace\n");

            // Seed phase
            for (int i = 0; i < seedPopulationSize; i++) {
                logger.info("[SEED {}/{}] Recording random execution...", i + 1, seedPopulationSize);
                Trace result = runBurnTest(null, "seed_" + i, errorsWriter);
                if (result != null && !result.isEmpty()) {
                    logger.info("[SEED {}/{}] Recorded {} events", i + 1, seedPopulationSize, result.size());
                    workQueue.add(result);
                } else {
                    logger.warn("[SEED {}/{}] No trace produced", i + 1, seedPopulationSize);
                }
            }

            // Main fuzzing loop
            for (int i =
                 0; i < iterations; i++) {
                if (maxDurationMs > 0 && System.currentTimeMillis() - startTime >= maxDurationMs) {
                    logger.info("=== FUZZER TIME LIMIT REACHED after {} iterations ===", i);
                    break;
                }

                Trace schedule;
                if (randomSchedule) {
                    Trace fresh = runBurnTest(null, "fresh_" + i, errorsWriter);
                    schedule = (fresh != null && !fresh.isEmpty()) ? generateRandomSeed(fresh) : null;
                    logger.info("[ITER {}/{}] RANDOM-SCHED ({} events) | workQueue ignored",
                                i + 1, iterations, schedule != null ? schedule.size() : 0);
                } else {
                    boolean queueEmpty = workQueue.isEmpty();
                    if (queueEmpty) {
                        Trace fresh = runBurnTest(null, "reseed_" + i, errorsWriter);
                        schedule = (fresh != null && !fresh.isEmpty()) ? generateRandomSeed(fresh) : null;
                    } else {
                        schedule = workQueue.poll();
                    }
                    String mode = schedule != null ? "REPLAY (" + schedule.size() + " events)" : "RANDOM";
                    logger.info("[ITER {}/{}] {} | workQueue={}", i + 1, iterations, mode, workQueue.size());
                    if (queueEmpty)
                        writeRepopulate(i, repopulateWriter);
                }

                if (schedule != null)
                    savePending(schedule, "iter_" + i, pendingWriter);

                Trace result = runBurnTest(schedule, "iter_" + i, errorsWriter);
                if (result == null || result.isEmpty()) {
                    logger.warn("[ITER {}/{}] No trace produced", i + 1, iterations);
                    continue;
                }

                logger.info("[ITER {}/{}] Result: {} events", i + 1, iterations, result.size());
                saveTrace(result, "iter" + i + "_execution", traceWriter, jsonlWriter, jsonWriter);

                // TLC and predicate coverage are always both computed and logged, regardless of
                // which one (if either) drives mutation energy - so the two are always directly
                // comparable in coverage.csv / predicate_coverage.csv for the same run.
                Integer tlcNewStates = null;
                if (guider != null) {
                    tlcNewStates = guider.check(result);
                    csvWriter.write(i + "," + guider.totalSeenStates() + "\n");
                    csvWriter.flush();
                }
                int predicateNewStates = predicateGuider.check(result);
                predicateCsvWriter.write(i + "," + predicateGuider.totalSeenStates() + "\n");
                predicateCsvWriter.flush();

                Integer energySource = usePredicateGuidance ? (Integer) predicateNewStates : tlcNewStates;
                String energyLabel = usePredicateGuidance ? "PREDICATE" : "TLC";
                boolean hasEnergySource = guided && energySource != null;

                if (!randomSchedule && hasEnergySource && energySource > 0) {
                    int count = Math.max(0, Math.min(energySource * mutationsPerTrace, maxQueueSize - workQueue.size()));
                    List<Trace> mutants = mutate(result, count);
                    logger.info("[ITER {}/{}] {}: {} new states → {} mutants | totalSeen(TLC)={} totalSeen(PREDICATE)={}",
                                i + 1, iterations, energyLabel, energySource, mutants.size(),
                                guider != null ? guider.totalSeenStates() : "n/a", predicateGuider.totalSeenStates());
                    workQueue.addAll(mutants);
                } else if (!randomSchedule && hasEnergySource) {
                    logger.debug("[ITER {}/{}] {}: no new states, skipping mutation", i + 1, iterations, energyLabel);
                } else {
                    logger.info("[ITER {}/{}] totalSeen(TLC)={} totalSeen(PREDICATE)={}",
                                i + 1, iterations, guider != null ? guider.totalSeenStates() : "n/a", predicateGuider.totalSeenStates());
                }
                if (!randomSchedule && !hasEnergySource) {
                    List<Trace> mutants = mutate(result);
                    logger.info("[ITER {}/{}] Generated {} mutants", i + 1, iterations, mutants.size());
                    workQueue.addAll(mutants);
                }

                if (!randomSchedule && reseedFrequency > 0 && i > 0 && i % reseedFrequency == 0) {
                    logger.info("[RESEED] Iteration {}: generating {} random seeds", i, seedPopulationSize);
                    workQueue.clear();
                    for (int s = 0; s < seedPopulationSize; s++) {
                        Trace fresh = runBurnTest(null, "reseed_" + i + "_" + s, errorsWriter);
                        if (fresh != null && !fresh.isEmpty())
                            workQueue.add(generateRandomSeed(fresh));
                    }
                }
            }

        } catch (IOException e) {
            logger.error("Session file I/O error: {}", e.getMessage(), e);
        }

        logger.info("=== FUZZER DONE === totalSeenStates(TLC)={} totalSeenStates(PREDICATE)={} | workQueue remaining: {} | trace: {} | jsonl: {} | json: {} | coverage: {} | predicateCoverage: {} | pending: {} | repopulate: {} | errors: {}",
                    guider != null ? guider.totalSeenStates() : "n/a", predicateGuider.totalSeenStates(),
                    workQueue.size(), traceFile, jsonlFile, jsonFile, csvFile, predicateCsvFile, pendingFile, repopulateFile, errorsFile);
    }

    /**
     * Run a burn test, optionally guided by a schedule.
     * Always records the resulting trace.
     */
    private Trace runBurnTest(Trace schedule, String runId, BufferedWriter errorsWriter) {
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
        BurnTestBase.allowEphemeralReads = false;
        // Fixed coordinator pool: only nodes [1..operations] ever submit transactions.
        // Remaining nodes still participate in consensus/replication but never coordinate.
        // This prevents reseeds from introducing new coordinator identities as fake TLC state variation.
        // Alternative: round-robin (count % operations) in BurnTestBase.generate() for fully deterministic assignment.
        BurnTestBase.coordinatorNodes = defaultNodes(operations);
        try {
            BurnTestBase.burn(
                new DefaultRandom(runSeed),
                topologyFactory,
                defaultClients(),
                defaultNodes(numNodes),
                2, // keys (2 = minimum to avoid infinite loop in randomKey; ensures near-total overlap)
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
                InMemoryJournal::new,
                crashes
            );
        } catch (Throwable t) {
            logger.error("  [{}] Burn test failed: {}", runId, t.getMessage(), t);
            writeError(runId, runSeed, t, errorsWriter);
            return null;
        } finally {
            BurnTestBase.allowEphemeralReads = true;
        }

        return recorder.trace();
    }

    public List<Trace> mutate(Trace schedule) {
        return mutate(schedule, mutationsPerTrace);
    }

    private List<Trace> mutate(Trace schedule, int count) {
        List<Trace> mutants = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Trace mutant = applyRandomMutation(schedule);
            if (mutant != null)
                mutants.add(mutant);
        }
        logger.info("  Mutated {}/{} (from {} events)", mutants.size(), count, schedule.size());
        return mutants;
    }

    /**
     * Generate a random seed trace in the style of ModelFuzz:
     * - keep client submit events (from=-1) to preserve transaction identity
     * - fill the rest of the schedule with synthetic Deliver events targeting random nodes
     * - interleave submits at random positions, preserving their relative order
     * - apply one crash/restart mutation
     */
    private Trace generateRandomSeed(Trace base) {
        List<TraceEvent> submits = new ArrayList<>();
        for (TraceEvent e : base.events()) {
            if (e instanceof TraceEvent.Deliver) {
                TraceEvent.Deliver d = (TraceEvent.Deliver) e;
                if (d.from.id == -1)
                    submits.add(e);
            }
        }

        int numSynthetic = Math.max(1, (traceEventBudget > 0 ? traceEventBudget : base.size()) - 20);
        List<TraceEvent> synthetic = new ArrayList<>(numSynthetic);
        long eventId = 1;
        long ts = 1;
        for (int k = 0; k < numSynthetic; k++) {
            Node.Id to = new Node.Id(1 + random.nextInt(numNodes));
            synthetic.add(new TraceEvent.Deliver(eventId++, ts++, eventId, new Node.Id(0), to,
                    null, null, "Synthetic", Integer.MIN_VALUE, Integer.MIN_VALUE, 0, "{}"));
        }
        Collections.shuffle(synthetic, random);

        // Insert client submits at random positions, preserving their relative order
        List<TraceEvent> events = new ArrayList<>(synthetic);
        for (TraceEvent submit : submits) {
            int pos = events.isEmpty() ? 0 : random.nextInt(events.size() + 1);
            events.add(pos, submit);
        }

        // Ensure the first event is a client submit
        boolean firstIsSubmit = !events.isEmpty() && events.get(0) instanceof TraceEvent.Deliver
                && ((TraceEvent.Deliver) events.get(0)).from.id == -1;
        if (!firstIsSubmit) {
            for (int k = 1; k < events.size(); k++) {
                TraceEvent e = events.get(k);
                if (e instanceof TraceEvent.Deliver && ((TraceEvent.Deliver) e).from.id == -1) {
                    events.add(0, events.remove(k));
                    break;
                }
            }
        }

        Trace seed = new Trace(base.header(), events);

        // Add one crash/restart pair for variety
        List<TraceEvent> withCrash = new ArrayList<>(seed.events());
        Trace afterCrash = insertCrash(seed, withCrash);
        if (afterCrash != null) {
            List<TraceEvent> withRestart = new ArrayList<>(afterCrash.events());
            Trace afterRestart = insertRestart(afterCrash, withRestart);
            if (afterRestart != null)
                return afterRestart;
            return afterCrash;
        }
        return seed;
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
        Trace result = switch (mutationType) {
            case 0 -> swapEvents(schedule, events);
            case 1 -> insertCrash(schedule, events);
            case 2 -> insertRestart(schedule, events);
            default -> null;
        };
        if (result == null && mutationType != 0) {
            logger.info("    Falling back to SWAP");
            result = swapEvents(schedule, events);
        }
        return result;
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
        // Collect nodes that have a Crash with no subsequent Recover (still down at end of trace)
        List<Node.Id> crashedNodes = new ArrayList<>();
        for (TraceEvent e : events) {
            if (e.getEventType() == TraceEvent.TraceEventType.CRASH)
                crashedNodes.add(((TraceEvent.Crash) e).node);
            else if (e.getEventType() == TraceEvent.TraceEventType.RECOVER)
                crashedNodes.remove(((TraceEvent.Recover) e).node);
        }
        if (crashedNodes.isEmpty()) {
            logger.info("    RESTART skipped: no crashed nodes in trace");
            return null;
        }

        Node.Id node = crashedNodes.get(random.nextInt(crashedNodes.size()));
        // Insert after the last Crash for this node
        int lastCrashPos = 0;
        for (int i = 0; i < events.size(); i++) {
            if (events.get(i).getEventType() == TraceEvent.TraceEventType.CRASH
                    && ((TraceEvent.Crash) events.get(i)).node.equals(node))
                lastCrashPos = i;
        }
        int position = lastCrashPos + 1 + (events.size() > lastCrashPos + 1 ? random.nextInt(events.size() - lastCrashPos - 1) : 0);
        long eventId = events.stream().mapToLong(e -> e.eventId).max().orElse(0) + 1;
        long timestamp = events.get(position - 1).timestamp;

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

    private void writeError(String runId, long seed, Throwable t, BufferedWriter errorsWriter) {
        try {
            StringWriter sw = new StringWriter();
            t.printStackTrace(new PrintWriter(sw));
            // RFC 4180: wrap in double-quotes, escape internal double-quotes by doubling them
            String quotedTrace = "\"" + sw.toString().replace("\"", "\"\"") + "\"";
            errorsWriter.write(runId + "," + seed + "," + t.getClass().getName() + "," + quotedTrace + "\n");
            errorsWriter.flush();
        } catch (IOException e) {
            logger.warn("  Failed to write error entry for {}: {}", runId, e.getMessage());
        }
    }

    private void writeRepopulate(int iteration, BufferedWriter repopulateWriter) {
        try {
            repopulateWriter.write(iteration + "\n");
            repopulateWriter.flush();
        } catch (IOException e) {
            logger.warn("  Failed to write repopulate entry for iteration {}: {}", iteration, e.getMessage());
        }
    }

    private void savePending(Trace schedule, String label, BufferedWriter pendingWriter) {
        try {
            pendingWriter.write("=== PENDING " + label + " ===\n");
            pendingWriter.write(schedule.toFullString());
            pendingWriter.write("\n\n");
            pendingWriter.flush();
        } catch (IOException e) {
            logger.warn("  Failed to append pending schedule {}: {}", label, e.getMessage());
        }
    }

    private void saveTrace(Trace trace, String label, BufferedWriter traceWriter, BufferedWriter jsonlWriter, BufferedWriter jsonWriter) {
        try {
            // traceWriter.write("=== " + label + " ===\n");
            // traceWriter.write(trace.toFullString());
            // traceWriter.write("\n\n");
            // traceWriter.flush();

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
