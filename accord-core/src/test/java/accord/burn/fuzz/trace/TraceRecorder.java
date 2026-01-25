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

    private final Trace trace;
    private final AtomicLong nextEventId = new AtomicLong(1);
    private final AtomicLong nextMessageId = new AtomicLong(1);
    private final AtomicLong logicalClock = new AtomicLong(0);

    //TODO: Remove this when timeouts are gone
    private final Map<WeakMessageKey, Integer> tupleSequences = new HashMap<>();

    public TraceRecorder(Trace trace) {
        this.trace = Objects.requireNonNull(trace, "trace");
    }

    /**
     * Create a new recorder with a fresh trace
     */
    public TraceRecorder(long seed, int nodeCount, int operationCount, String version) {
        this(new Trace(new Trace.Header(seed, nodeCount, operationCount, version)));
    }

    public Trace trace() {
        return trace;
    }

    public long currentTimestamp() {
        return logicalClock.get();
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

    /**
     * Record a message delivery event
     */
    public TraceEvent.Deliver recordDeliver(long messageId, Node.Id from, Node.Id to, Message message, long requestId, long replyId) {
        long eventId = nextEventId.getAndIncrement();
        long timestamp = tick();
        MessageType type = message != null ? message.type() : null;
        TxnId txnId = TxnIdExtractor.extract(message);
        String messageClass = message != null ? message.getClass().getSimpleName() : "null";

        // Get and increment sequence for this tuple
        WeakMessageKey key = new WeakMessageKey(from, to, type, txnId);
        int sequence = tupleSequences.compute(key, (k, v) -> v == null ? 0 : v + 1);

        TraceEvent.Deliver event = new TraceEvent.Deliver(eventId, timestamp, messageId, from, to,
                type, txnId, messageClass, requestId, replyId, sequence);
        trace.add(event);
        return event;
    }

    /**
     * Record a message drop event
     */
    public TraceEvent.Drop recordDrop(long messageId, Node.Id from, Node.Id to, Message message) {
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
    public TraceEvent.Crash recordCrash(Node.Id node) {
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
    public TraceEvent.Recover recordRecover(Node.Id node) {
        long eventId = nextEventId.getAndIncrement();
        long timestamp = tick();

        TraceEvent.Recover event = new TraceEvent.Recover(eventId, timestamp, node);
        trace.add(event);
        return event;
    }

    /**
     * Record a client operation event
     */
    public TraceEvent.ClientOp recordClientOp(long opId, Node.Id coordinator, @Nullable TxnId txnId, String description) {
        long eventId = nextEventId.getAndIncrement();
        long timestamp = tick();

        TraceEvent.ClientOp event = new TraceEvent.ClientOp(
                eventId, timestamp, opId, coordinator, txnId, description
        );
        trace.add(event);
        return event;
    }

    /**
     * Record a timer event
     */
    public TraceEvent.Timer recordTimer(long timerId, Node.Id node, String timerType) {
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
        return String.format("TraceRecorder{events=%d, states=%d, clock=%d}", eventCount(), uniqueStateCount(), logicalClock.get());
    }
}
