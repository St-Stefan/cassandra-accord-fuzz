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

package accord.burn.fuzz.trace;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import accord.burn.fuzz.CrashSimulator;
import accord.impl.basic.Packet;
import accord.impl.basic.Pending;
import accord.impl.basic.PendingQueue;
import accord.primitives.TxnId;

/**
 * A PendingQueue wrapper that supports deterministic replay of executions and exploration
 * of alternative schedules by mutating recorded traces.
 * <p>
 * For replay, we use weak matching based on (from, to, messageType, txnId, sequenceInTuple)
 * rather than exact message IDs, since message IDs are not stable across runs.
 */
public class GuidedPendingQueue implements PendingQueue {
    private static final Logger logger = LoggerFactory.getLogger(GuidedPendingQueue.class);

    public enum Mode {
        RECORD,
        REPLAY
    }

    private final PendingQueue delegate;
    private final Mode mode;
    private final TraceRecorder recorder;
    @Nullable
    private final Trace replayTrace;
    @Nullable
    private final CrashSimulator crashSimulator;

    //Maps Packet to its assigned messageId for correlation
    private final Map<Packet, Long> packetToMessageId = new HashMap<>();

    // Skip messages that are not relevant to the Accord consensus protocol (TLA+ spec)
    // NOTE: InformDurable (INFORM_DURABLE_REQ) seems to be part of every request, so keep it for now
    // TODO: Investigate all message types, don't eyeball here
    private static final Set<String> BYPASS_REPLAY_TYPE_NAMES = Set.of(
            // Skip durability/garbage collection messages
            "DurableBefore",
            "DurableBeforeReply",
            "GetDurableBefore",
            "SetShardDurable",
            "SetGloballyDurable",
            "NotifyWaitingOn",

            "CheckStatus",
            "CheckStatusOk",
            "CheckStatusOkFull"
    );

    //Current position in the replay trace
    private int replayIndex = 0;

    // Skip a trace event if we fail to match it within this logical-time window
    private static final long REPLAY_CHOICE_TIMEOUT_MILLIS = 500;
    private long lastReplayChoiceTimeMillis = Long.MIN_VALUE;

    //Items that are pending but not yet eligible for replay
    private final LinkedList<Pending> mailbox = new LinkedList<>();

    //Stats
    private int deliveredCount = 0;
    private int droppedCount = 0;

    /**
     * Create a GuidedPendingQueue in RECORD mode
     */
    public static GuidedPendingQueue forRecording(PendingQueue delegate, TraceRecorder recorder, CrashSimulator crashSimulator) {
        return new GuidedPendingQueue(delegate, Mode.RECORD, recorder, null, crashSimulator);
    }

    /**
     * Create a GuidedPendingQueue in REPLAY mode
     */
    public static GuidedPendingQueue forReplay(PendingQueue delegate, TraceRecorder recorder, Trace replayTrace, @Nullable CrashSimulator crashSimulator) {
        Objects.requireNonNull(replayTrace, "replayTrace required for REPLAY mode");
        return new GuidedPendingQueue(delegate, Mode.REPLAY, recorder, replayTrace, crashSimulator);
    }

    private GuidedPendingQueue(PendingQueue delegate, Mode mode, TraceRecorder recorder, @Nullable Trace replayTrace, @Nullable CrashSimulator crashSimulator) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.mode = Objects.requireNonNull(mode, "mode");
        this.recorder = Objects.requireNonNull(recorder, "recorder");
        this.replayTrace = replayTrace;
        this.crashSimulator = crashSimulator;
    }

    public Mode mode() {
        return mode;
    }

    public TraceRecorder recorder() {
        return recorder;
    }

    // Just get the name of the class for now
    private boolean shouldBypassReplay(Pending item) {
        if (!(item instanceof Packet))
            return false;

        Packet packet = (Packet) item;
        if (packet.message == null)
            return false;

        String className = packet.message.getClass().getSimpleName();
        return BYPASS_REPLAY_TYPE_NAMES.contains(className) || packet.dst.equals(packet.src);
    }

    public Trace trace() {
        return recorder.trace();
    }

    /**
     * Allocate and track a message ID for a packet.
     * <p>
     * IMPORTANT: For requests/replies we prefer using the existing stable id from the Packet
     * (requestId for requests, replyId for replies). This makes replay matching deterministic.
     */
    public long assignMessageId(Packet packet) {
        return packetToMessageId.computeIfAbsent(packet, GuidedPendingQueue::stableMessageId);
    }

    private static long stableMessageId(Packet packet) {
        final long sentinel = Integer.MIN_VALUE;

        // Replies use replyId; requests use requestId
        if (packet.replyId != sentinel) return packet.replyId;
        if (packet.requestId != sentinel) return packet.requestId;

        return System.identityHashCode(packet);
    }

    public long getMessageId(Packet packet) {
        Long id = packetToMessageId.get(packet);
        if (id == null) id = assignMessageId(packet);
        return id;
    }

    @Override
    public Pending poll() {
        if (mode == Mode.RECORD) {
            return pollRecord();
        } else {
//            if (pollCallCount == 0) {
//                logger.info("First poll() call in REPLAY mode - trace has {} events", replayTrace != null ? replayTrace.size() : "null");
//            }
            return pollReplay();
        }
    }

    private Pending pollRecord() {
        Pending item = delegate.poll();
        if (item == null)
            return null;

        // Record the event based on the item type
        recordEvent(item);
        return item;
    }

    // Debug logging control
    private static final boolean DEBUG_REPLAY = Boolean.getBoolean("accord.replay.debug") || true;
    private int pollCallCount = 0;
    private int emptyPollCount = 0;

    private void debugLog(String msg) {
        if (DEBUG_REPLAY) {
            logger.info("[REPLAY] " + msg);
        }
    }

    private Pending pollReplay() {
        pollCallCount++;
        long now = delegate.nowInMillis();
        if (lastReplayChoiceTimeMillis == Long.MIN_VALUE)
            lastReplayChoiceTimeMillis = now;

        // Use iterator to find matching items
        // Draining messes up the time because of the requeues
        // This preserves queue order and logical time progression

        // If we have a trace to follow, look for matching packet
        if (replayTrace != null && replayIndex < replayTrace.size()) {
            TraceEvent expected = replayTrace.get(replayIndex);
            debugLog("  Looking for trace event #" + replayIndex + ": " + expected + ", count: " + pollCallCount + " calls, time: " + now + "ms, last choice at: " + lastReplayChoiceTimeMillis);
            debugLog(" Delegate stats: " + delegate.size());

            //Check mailbox first for matching items
            Iterator<Pending> mailboxIt = mailbox.iterator();
            int mailboxCandidateNum = 0;
            while (mailboxIt.hasNext()) {
                Pending p = mailboxIt.next();
                boolean isMatch = matches(p, expected);
                debugLog("    Mailbox candidate " + mailboxCandidateNum + ": " + formatPending(p) + " -> match=" + isMatch);
                mailboxCandidateNum++;
                if (isMatch) {
                    mailboxIt.remove();
                    replayIndex++;
                    lastReplayChoiceTimeMillis = now;
                    recordEvent(p);
                    debugLog("  MATCHED in mailbox! Returning: " + formatPending(p) + ", advancing replayIndex to " + replayIndex);
                    return p;
                }
            }

            // Snapshot delegate contents to avoid ConcurrentModificationException
            List<Pending> snapshot = new ArrayList<>();
            for (Iterator<Pending> it = delegate.iterator(); it.hasNext(); )
                snapshot.add(it.next());

            Pending matched = null;
            List<Pending> toMailbox = new ArrayList<>();
            int candidateNum = 0;
            for (Pending p : snapshot) {
                if (p instanceof Packet && !shouldBypassReplay(p)) {
                    boolean isMatch = matches(p, expected);
                    //debugLog("    Candidate " + candidateNum + ": " + formatPending(p) + " -> match=" + isMatch);
                    candidateNum++;
                    if (matched == null && isMatch) {
                        matched = p;
                    } else {
                        toMailbox.add(p);
                        //debugLog("    Not a match, moved to mailbox: " + formatPending(p));
                    }
                }
            }

            // Remove matched + moved-to-mailbox items from delegate after iteration
            if (matched != null) {
                delegate.remove(matched);
                for (Pending p : toMailbox) {
                    delegate.remove(p);
                    mailbox.add(p);
                }
                replayIndex++;
                lastReplayChoiceTimeMillis = now;
                recordEvent(matched);
                //debugLog("  MATCHED! Returning: " + formatPending(matched) + ", advancing replayIndex to " + replayIndex);
                return matched;
            }
            // No match found — still move non-matching packets to mailbox
            for (Pending p : toMailbox) {
                delegate.remove(p);
                mailbox.add(p);
            }

            // If this replay choice is stale in logical time, advance to next expected event
            if (now - lastReplayChoiceTimeMillis >= REPLAY_CHOICE_TIMEOUT_MILLIS && replayIndex>0) {
                replayIndex++;
                lastReplayChoiceTimeMillis = now;
                return null;
            }
        }

        // Look for bypassed packets (they don't participate in replay ordering)
        // Snapshot to avoid ConcurrentModificationException
        List<Pending> bypassSnapshot = new ArrayList<>();
        for (Iterator<Pending> it = delegate.iterator(); it.hasNext(); )
            bypassSnapshot.add(it.next());

        for (Pending p : bypassSnapshot) {
            if (shouldBypassReplay(p)) {
                delegate.remove(p);
                recordEvent(p);
                //debugLog("  Returning bypassed packet: " + p);
                return p;
            }
        }

        // If trace exhausted, return any available packet (mailbox first, then delegate)
        if (replayTrace == null || replayIndex >= replayTrace.size()) {
            if (!mailbox.isEmpty()) {
                Pending p = mailbox.removeFirst();
                recordEvent(p);
                debugLog("  Trace exhausted, returning from mailbox: " + formatPending(p));
                return p;
            }

            List<Pending> exhaustedSnapshot = new ArrayList<>();
            for (Iterator<Pending> it = delegate.iterator(); it.hasNext(); )
                exhaustedSnapshot.add(it.next());

            for (Pending p : exhaustedSnapshot) {
                if (p instanceof Packet) {
                    delegate.remove(p);
                    recordEvent(p);
                    return p;
                }
            }
        }

        // Fix for accidentally consuming packets
        Pending next = delegate.poll();
        if (next != null) {
            if (next instanceof Packet) {
                // Put it back with no delay so it stays at the front
                // Doesn't matter since we try to match anyhow
                delegate.addNoDelay(next);
                //debugLog("  SOMEHOW WE STILL HAVE A PACKET " + formatPending(next));
                return null;
            }
            //debugLog("  Returning runnable to generate packets: " + next.getClass().getSimpleName());
            return next;
        }

        // Putting runnables last is also based on an eyeballed assumption
        // There should be less network messages than runnables

        debugLog(" Nothing to return, returning null");
        return null;
    }

    private String formatPending(Pending p) {
        if (p instanceof Packet) {
            Packet pkt = (Packet) p;
            String msgType = pkt.message != null ? String.valueOf(pkt.message.type()) : "null";
            String msgClass = pkt.message != null ? pkt.message.getClass().getSimpleName() : "null";
            TxnId txnId = pkt.message != null ? TxnIdExtractor.extract(pkt.message) : null;
            return String.format("Packet{%s->%s, type=%s, class=%s, txn=%s}",
                    pkt.src, pkt.dst, msgType, msgClass, txnId);
        }
        return p.toString();
    }

    /**
     * Check if a pending item matches an expected trace event.
     */
    private boolean matches(Pending pending, TraceEvent expected) {
        if (!(pending instanceof Packet))
            return false;

        Packet packet = (Packet) pending;

        if (expected instanceof TraceEvent.Deliver) {
            TraceEvent.Deliver deliver = (TraceEvent.Deliver) expected;

            // Match on: source, dest
            if (!packet.src.equals(deliver.from)) return false;
            if (!packet.dst.equals(deliver.to)) return false;

            return true;
        } else if (expected instanceof TraceEvent.Drop) {
            TraceEvent.Drop drop = (TraceEvent.Drop) expected;

            if (!packet.src.equals(drop.from)) return false;
            if (!packet.dst.equals(drop.to)) return false;

            return true;
        }

        return false;
    }

    /**
     * Record an event for a pending item that was polled.
     * Only Packet events are included in traces.
     * Packets that bypass replay (internal/self-addressed) are not recorded.
     */
    private void recordEvent(Pending item) {
        if (!(item instanceof Packet))
            return;

        // Don't record packets that are bypassed (e.g. self-addressed src==dst, or bypass type names)
        if (shouldBypassReplay(item))
            return;

        Packet packet = (Packet) item;
        long messageId = getMessageId(packet);

        boolean shouldDrop = crashSimulator != null && !crashSimulator.shouldDeliver(packet.src, packet.dst);

        if (shouldDrop) {
            recorder.recordDrop(messageId, packet.src, packet.dst, packet.message);
            droppedCount++;
        } else {
            recorder.recordDeliver(messageId, packet.src, packet.dst, packet.message, packet.requestId, packet.replyId);
            deliveredCount++;
        }
    }

    @Override
    public void add(Pending item) {
        if (item instanceof Packet) {
            assignMessageId((Packet) item);
        }
        delegate.add(item);
    }

    @Override
    public void addNoDelay(Pending item) {
        if (item instanceof Packet) {
            assignMessageId((Packet) item);
        }
        delegate.addNoDelay(item);
    }

    @Override
    public void add(Pending item, long delay, TimeUnit units) {
        if (item instanceof Packet) {
            assignMessageId((Packet) item);
        }
        delegate.add(item, delay, units);
    }

    @Override
    public void preregister(Pending item) {
        delegate.preregister(item);
    }

    @Override
    public boolean remove(Pending item) {
        if (item instanceof Packet)
            packetToMessageId.remove(item);
        return delegate.remove(item);
    }

    @Override
    public List<Pending> drain(Predicate<Pending> toDrain) {
        List<Pending> drained = delegate.drain(toDrain);
        for (Pending p : drained) {
            if (p instanceof Packet)
                packetToMessageId.remove(p);
        }
        return drained;
    }

    @Override
    public int size() {
        return delegate.size();
    }

    @Override
    public long nowInMillis() {
        return delegate.nowInMillis();
    }

    @Override
    public boolean hasNonRecurring() {
        return delegate.hasNonRecurring();
    }

    @Override
    public Iterator<Pending> iterator() {
        return delegate.iterator();
    }

    public int deliveredCount() {
        return deliveredCount;
    }

    public int droppedCount() {
        return droppedCount;
    }

    public boolean isReplayComplete() {
        return mode == Mode.REPLAY && replayTrace != null && replayIndex >= replayTrace.size();
    }

    @Override
    public String toString() {
        return String.format("GuidedPendingQueue{mode=%s, delivered=%d, dropped=%d, replayIdx=%d}",
                mode, deliveredCount, droppedCount, replayIndex);
    }
}
