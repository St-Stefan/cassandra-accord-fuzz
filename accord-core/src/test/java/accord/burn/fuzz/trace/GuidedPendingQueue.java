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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import javax.annotation.Nullable;

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

    //Current position in the replay trace
    private int replayIndex = 0;

    //Items that are pending but not yet eligible for replay
    private final List<Pending> deferredItems = new ArrayList<>();

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

    private Pending pollReplay() {
        // Drain all pending items
        List<Pending> items = new ArrayList<>();
        Pending item;
        while ((item = delegate.poll()) != null)
            items.add(item);

        if (items.isEmpty())
            return null;

        List<Pending> runnables = new ArrayList<>();
        List<Pending> packets = new ArrayList<>();
        for (Pending p : items) {
            if (p instanceof Packet)
                packets.add(p);
            else
                runnables.add(p);
        }

        if (!runnables.isEmpty()) {
            Pending runnable = runnables.remove(0);
            // Put everything else back
            for (Pending r : runnables) delegate.addNoDelay(r);
            for (Pending p : packets) delegate.addNoDelay(p);
            return runnable;
        }

        if (replayTrace == null || replayIndex >= replayTrace.size()) {
            // Trace exhausted; just return first packet
            if (!packets.isEmpty()) {
                Pending first = packets.remove(0);
                for (Pending p : packets) delegate.addNoDelay(p);
                recordEvent(first);
                return first;
            }
            return null;
        }

        TraceEvent expected = replayTrace.get(replayIndex);
        Pending match = null;
        for (int i = 0; i < packets.size(); i++) {
            if (matches(packets.get(i), expected)) {
                match = packets.remove(i);
                break;
            }
        }

        // Put non-matching packets back
        for (Pending p : packets)
            delegate.addNoDelay(p);

        if (match != null) {
            replayIndex++;
            recordEvent(match);
            return match;
        }

        // Allow the simulation to continue even if the execution diverges
        // Still doesn't work
        if (!packets.isEmpty()) {
            replayIndex++; // Skip this trace event
            Pending first = packets.remove(0);
            for (Pending p : packets) delegate.addNoDelay(p);
            recordEvent(first);
            return first;
        }

        // No packets at all - return null
        return null;
    }

    /**
     * Check if a pending item matches an expected trace event.
     * <p>
     * SIMPLE matching: (from, to, messageType, messageClass, txnId)
     * No sequence numbers for now - just find the first matching packet.
     */
    private boolean matches(Pending pending, TraceEvent expected) {
        if (!(pending instanceof Packet))
            return false;

        Packet packet = (Packet) pending;

        if (expected instanceof TraceEvent.Deliver) {
            TraceEvent.Deliver deliver = (TraceEvent.Deliver) expected;

            // Match on: from, to, messageType, messageClass
            if (!packet.src.equals(deliver.from)) return false;
            if (!packet.dst.equals(deliver.to)) return false;
            if (packet.message == null) return false;
            if (packet.message.type() != deliver.messageType) return false;
            if (!packet.message.getClass().getSimpleName().equals(deliver.messageClass)) return false;

            // txnId matching (must match if trace has one)
            TxnId packetTxnId = TxnIdExtractor.extract(packet.message);
            if (deliver.txnId != null && !deliver.txnId.equals(packetTxnId))
                return false;

            return true;
        } else if (expected instanceof TraceEvent.Drop) {
            TraceEvent.Drop drop = (TraceEvent.Drop) expected;

            if (!packet.src.equals(drop.from)) return false;
            if (!packet.dst.equals(drop.to)) return false;
            if (packet.message == null) return false;
            if (packet.message.type() != drop.messageType) return false;
            if (!packet.message.getClass().getSimpleName().equals(drop.messageClass)) return false;

            TxnId packetTxnId = TxnIdExtractor.extract(packet.message);
            if (drop.txnId != null && !drop.txnId.equals(packetTxnId))
                return false;

            return true;
        }

        return false;
    }

    /**
     * Record an event for a pending item that was polled.
     * Only Packet events are included in traces.
     */
    private void recordEvent(Pending item) {
        if (!(item instanceof Packet))
            return;

        Packet packet = (Packet) item;
        long messageId = getMessageId(packet);

        // Check if this should be dropped due to a crash
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
