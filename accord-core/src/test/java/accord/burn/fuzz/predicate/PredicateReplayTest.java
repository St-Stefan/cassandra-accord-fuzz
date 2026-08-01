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

package accord.burn.fuzz.predicate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import accord.api.ProtocolModifiers.Toggles;
import accord.burn.BurnTestBase;
import accord.burn.fuzz.CrashSimulator;
import accord.burn.fuzz.NoDelayQueue;
import accord.burn.fuzz.trace.GuidedPendingQueue;
import accord.burn.fuzz.trace.Trace;
import accord.burn.fuzz.trace.TraceRecorder;
import accord.impl.TopologyFactory;
import accord.impl.basic.InMemoryJournal;
import accord.impl.basic.PendingQueue;
import accord.local.Node;
import accord.primitives.Range;
import accord.primitives.TxnId;
import accord.utils.DefaultRandom;
import accord.utils.RandomSource;

import static accord.api.ProtocolModifiers.Toggles.SendStableMessages.TO_ALL;
import static accord.impl.PrefixedIntHashKey.forHash;
import static accord.impl.PrefixedIntHashKey.range;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs one real burn-test execution (same setup {@link accord.burn.fuzz.Fuzzer#runBurnTest} uses:
 * a {@link GuidedPendingQueue} in RECORD mode wrapping the real message queue) and prints every
 * predicate {@link PredicateTraceWalker} extracts from the resulting trace, at both abstraction
 * levels. This is a sanity checkpoint on a real trace before wiring an incremental state machine
 * on top - if the counts/classifications look wrong here, they'd be wrong there too.
 */
public class PredicateReplayTest {
    private static final Logger logger = LoggerFactory.getLogger(PredicateReplayTest.class);

    @Test
    public void replayAndPrintPredicates() throws IOException {
        long seed = 123L;
        int numNodes = 7;
        int operations = 3;
        int concurrency = 3;
        int quorum = numNodes / 2 + 1;
        // A coordinator never sends itself a network message (self-addressed packets are dropped
        // by GuidedPendingQueue.shouldBypassReplay), so the max sent/acked count observable in a
        // trace is numNodes - 1, not numNodes - see PredicateStateMachine's observableNodeCount.
        int observableNodeCount = numNodes - 1;

        Trace trace = runBurnTest(seed, numNodes, operations, concurrency);
        assertFalse(trace.isEmpty(), "expected a non-empty trace from the burn test");
        logger.info("Recorded trace: {} events", trace.size());
        logger.info("Wrote raw trace to {}", dumpTrace(trace, seed));

        PredicateTraceWalker walker = PredicateTraceWalker.of(trace);
        List<TxnId> transactions = new ArrayList<>(walker.transactions());
        assertFalse(transactions.isEmpty(), "expected at least one transaction to be attributed");

        // Run-independent id: same coordinator-grouped assignment Trace.toTlaJson uses, so this
        // id is directly comparable to the "id" field the JSON export would emit for the same txn.
        Map<TxnId, Integer> normalizedIds = TxnNormalizer.normalize(trace);

        for (TxnId txnId : transactions) {
            logger.info("txn {} (normalized id={}, coordinator={})", txnId, normalizedIds.get(txnId), txnId.node);
            Map<String, int[]> counts = walker.countsFor(txnId);
            for (Map.Entry<String, int[]> e : counts.entrySet()) {
                String stage = e.getKey();
                int sent = e.getValue()[0];
                int acked = e.getValue()[1];
                Object extent = StageClassifier.EXTENT.classify(sent, acked, quorum, observableNodeCount);
                Object reachedCompleted = StageClassifier.REACHED_COMPLETED.classify(sent, acked, quorum, observableNodeCount);
                logger.info("  {}: sent={} acked={}  extent={}  reached/completed={}",
                        stage, sent, acked, extent, reachedCompleted);
            }
        }

        assertTrue(transactions.stream().anyMatch(t -> !walker.stagesFor(t).isEmpty()),
                "expected at least one transaction to have reached at least one stage");

        int extentStates = PredicateStateMachine.replay(trace, StageClassifier.EXTENT).visitedStates().size();
        int reachedCompletedStates = PredicateStateMachine.replay(trace, StageClassifier.REACHED_COMPLETED).visitedStates().size();
        logger.info("Joint state coverage over {} events: EXTENT={} distinct states, REACHED_COMPLETED={} distinct states",
                trace.size(), extentStates, reachedCompletedStates);
        assertTrue(reachedCompletedStates <= extentStates);

        // PredicateGuider mirrors TlcGuider's check()/totalSeenStates() shape: the first call on a
        // trace reports every state it visits as new; a second call on the SAME trace (as would
        // happen if a mutant produced an identical predicate-level execution) must report none.
        PredicateGuider guider = new PredicateGuider(StageClassifier.EXTENT);
        int firstCheck = guider.check(trace);
        int secondCheck = guider.check(trace);
        logger.info("PredicateGuider on seed-42 trace: first check={} new states, totalSeenStates={}, repeat check={} new states",
                firstCheck, guider.totalSeenStates(), secondCheck);
        assertEquals(extentStates, firstCheck);
        assertEquals(extentStates, guider.totalSeenStates());
        assertEquals(0, secondCheck);
    }

    /**
     * Writes every raw event, one per line, so the printed predicate counts can be checked
     * against the actual trace rather than taken on faith. Deterministic for a fixed seed.
     */
    private static Path dumpTrace(Trace trace, long seed) throws IOException {
        Path dir = Path.of(System.getProperty("user.dir"), "build", "test-traces", "predicate");
        Files.createDirectories(dir);
        Path traceFile = dir.resolve("replay_seed" + seed + ".trace.txt");
        Files.writeString(traceFile, trace.toFullString(), StandardCharsets.UTF_8);
        return traceFile;
    }

    /**
     * Mirrors {@code Fuzzer.runBurnTest(null, ...)} (record mode, no replay schedule) minus the
     * fuzzer's file I/O and iteration bookkeeping - just enough to get one real {@link Trace}.
     */
    private static Trace runBurnTest(long seed, int numNodes, int operations, int concurrency) {
        Range full = range(forHash(0, BurnTestBase.HASH_RANGE_START),
                forHash(0, BurnTestBase.HASH_RANGE_END));
        TopologyFactory topologyFactory = new TopologyFactory(numNodes, full);

        TraceRecorder recorder = new TraceRecorder(seed, numNodes, operations, "predicate-replay-1.0");
        CrashSimulator crashes = new CrashSimulator();

        Toggles.setSendStableMessages(TO_ALL);
        Toggles.setPermitLocalExecution(false);
        BurnTestBase.allowEphemeralReads = false;
        BurnTestBase.coordinatorNodes = defaultNodes(operations);
        try {
            BurnTestBase.burn(
                    new DefaultRandom(seed),
                    topologyFactory,
                    defaultClients(),
                    defaultNodes(numNodes),
                    2, // keys
                    1, // prefixes
                    operations,
                    concurrency,
                    (RandomSource rnd) -> {
                        PendingQueue delegate = new NoDelayQueue(rnd);
                        return GuidedPendingQueue.forRecording(delegate, recorder, crashes);
                    },
                    InMemoryJournal::new,
                    crashes
            );
        } finally {
            BurnTestBase.allowEphemeralReads = true;
        }

        return recorder.trace();
    }

    private static List<Node.Id> defaultClients() {
        return List.of(new Node.Id(-1));
    }

    private static List<Node.Id> defaultNodes(int count) {
        List<Node.Id> nodes = new ArrayList<>(count);
        for (int i = 1; i <= count; i++)
            nodes.add(new Node.Id(i));
        return nodes;
    }
}
