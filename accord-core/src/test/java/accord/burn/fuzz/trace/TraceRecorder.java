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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import javax.annotation.Nullable;

import accord.local.Node;
import accord.messages.Message;
import accord.messages.MessageType;
import accord.primitives.TxnId;


public class TraceRecorder {
    //TODO: Remove Timeouts, remove this
    public record WeakMessageKey(Node.Id from, Node.Id to, MessageType type, @Nullable TxnId txnId) {
    }

    private static final long NO_ID = Integer.MIN_VALUE;

    private final Trace trace;
    private final AtomicLong nextEventId = new AtomicLong(1);
    private final AtomicLong nextMessageId = new AtomicLong(1);
    private final AtomicLong logicalClock = new AtomicLong(0);
    private final int maxEvents;

    //TODO: Remove this when timeouts are gone
    private final Map<WeakMessageKey, Integer> tupleSequences = new HashMap<>();
    // Maps request message ID → txnId so reply messages (e.g. AcceptReply) can be correlated back.
    private final Map<Long, TxnId> requestTxnIds = new HashMap<>();

    public TraceRecorder(Trace trace, int maxEvents) {
        this.trace = Objects.requireNonNull(trace, "trace");
        this.maxEvents = maxEvents <= 0 ? Integer.MAX_VALUE : maxEvents;
    }

    /**
     * Create a new recorder with a fresh trace
     */
    public TraceRecorder(long seed, int nodeCount, int operationCount, String version) {
        this(seed, nodeCount, operationCount, version, 0);
    }

    public TraceRecorder(long seed, int nodeCount, int operationCount, String version, int maxEvents) {
        this(new Trace(new Trace.Header(seed, nodeCount, operationCount, version)), maxEvents);
    }

    public Trace trace() {
        return trace;
    }


    public long tick() {
        return logicalClock.incrementAndGet();
    }

    /**
     * Allocate a new message ID for tracking a message through the system
     */
    public long allocateMessageId() {
        return nextMessageId.getAndIncrement();
    }


    public boolean hasEventBudget() {
        return maxEvents != Integer.MAX_VALUE;
    }

    private boolean canRecordNextEvent() {
        return eventCount() < maxEvents;
    }

    /**
     * Record a message delivery event
     */
    public @Nullable TraceEvent.Deliver recordDeliver(long messageId, Node.Id from, Node.Id to, Message message, long requestId, long replyId) {
        if (!canRecordNextEvent())
            return null;

        long eventId = nextEventId.getAndIncrement();
        long timestamp = tick();
        MessageType type = message != null ? message.type() : null;
        TxnId txnId = TxnIdExtractor.extract(message);
        if (txnId == null && replyId != NO_ID)
            txnId = requestTxnIds.get(replyId);
        if (txnId != null && requestId != NO_ID)
            requestTxnIds.put(requestId, txnId);
        String messageClass = message != null ? message.getClass().getSimpleName() : "null";
        String fieldsJson = MessageTraceJson.toJson(message);

        // Get and increment sequence for this tuple
        WeakMessageKey key = new WeakMessageKey(from, to, type, txnId);
        int sequence = tupleSequences.compute(key, (k, v) -> v == null ? 0 : v + 1);

        TraceEvent.Deliver event = new TraceEvent.Deliver(eventId, timestamp, messageId, from, to,
                type, txnId, messageClass, requestId, replyId, sequence, fieldsJson);
        trace.add(event);
        return event;
    }

    /**
     * Record a message drop event
     */
    public @Nullable TraceEvent.Drop recordDrop(long messageId, Node.Id from, Node.Id to, Message message) {
        if (!canRecordNextEvent())
            return null;

        long eventId = nextEventId.getAndIncrement();
        long timestamp = tick();
        MessageType type = message != null ? message.type() : null;
        TxnId txnId = TxnIdExtractor.extract(message);
        String messageClass = message != null ? message.getClass().getSimpleName() : "null";

        // Get and increment sequence for this tuple
        WeakMessageKey key = new WeakMessageKey(from, to, type, txnId);
        int sequence = tupleSequences.compute(key, (k, v) -> v == null ? 0 : v + 1);

        TraceEvent.Drop event = new TraceEvent.Drop(eventId, timestamp, messageId, from, to,
                type, txnId, messageClass, sequence);
        trace.add(event);
        return event;
    }

    /**
     * Record a node crash event
     * Technically possible
     */
    public @Nullable TraceEvent.Crash recordCrash(Node.Id node) {
        if (!canRecordNextEvent())
            return null;

        long eventId = nextEventId.getAndIncrement();
        long timestamp = tick();

        TraceEvent.Crash event = new TraceEvent.Crash(eventId, timestamp, node);
        trace.add(event);
        return event;
    }

    /**
     * Record a node recovery event
     * Not to be confused with the recovery algorithm
     */
    public @Nullable TraceEvent.Recover recordRecover(Node.Id node) {
        if (!canRecordNextEvent())
            return null;

        long eventId = nextEventId.getAndIncrement();
        long timestamp = tick();

        TraceEvent.Recover event = new TraceEvent.Recover(eventId, timestamp, node);
        trace.add(event);
        return event;
    }

    /**
     * Record a timer event
     */
    public @Nullable TraceEvent.Timer recordTimer(long timerId, Node.Id node, String timerType) {
        if (!canRecordNextEvent())
            return null;

        long eventId = nextEventId.getAndIncrement();
        long timestamp = tick();

        TraceEvent.Timer event = new TraceEvent.Timer(
                eventId, timestamp, timerId, node, timerType
        );
        trace.add(event);
        return event;
    }

    /**
     * Record a state fingerprint at the current point in execution
     */
    public void recordState(long stateFingerprint) {
        trace.recordState(stateFingerprint);
    }

    public int eventCount() {
        return trace.size();
    }

    public int uniqueStateCount() {
        return trace.uniqueStateCount();
    }

    @Override
    public String toString() {
        return String.format("TraceRecorder{events=%d, states=%d, clock=%d, budget=%s}",
                eventCount(), uniqueStateCount(), logicalClock.get(), hasEventBudget() ? maxEvents : "unlimited");
    }
}
