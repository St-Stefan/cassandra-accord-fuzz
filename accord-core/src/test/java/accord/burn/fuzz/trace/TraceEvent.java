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

import java.util.Objects;
import javax.annotation.Nullable;

import accord.local.Node;
import accord.messages.MessageType;
import accord.primitives.TxnId;

/**
 * Represents a single event in an execution trace for trace-based fuzzing.
 */
public abstract class TraceEvent {
    public enum TraceEventType {
        DELIVER,
        DROP,
        CRASH,
        RECOVER,
        CLIENT_OP,
        TIMER
    }

    /**
     * Unique identifier for this event, stable across replay
     */
    public final long eventId;

    /**
     * Logical clock timestamp when this event occurred
     */
    public final long timestamp;

    protected TraceEvent(long eventId, long timestamp) {
        this.eventId = eventId;
        this.timestamp = timestamp;
    }

    /**
     * Returns the kind of this event
     */
    public abstract TraceEventType getEventType();

    public abstract boolean isDependentWith(TraceEvent other);

    @Nullable
    public abstract Node.Id primaryNode();

    @Nullable
    public Node.Id secondaryNode() {
        return null;
    }

    @Nullable
    public TxnId txnId() {
        return null;
    }

    public static final class Deliver extends TraceEvent {
        public final long messageId;
        public final Node.Id from;
        public final Node.Id to;
        public final MessageType messageType;
        @Nullable
        public final TxnId txnId;
        // Class name of the message for debugging/replay
        public final String messageClass;
        //Request ID for correlating replies
        public final long requestId;
        //Reply ID if this is a reply message
        public final long replyId;
        //Sequence number within (from, to, messageType, txnId) tuple for weak matching
        public final int sequenceInTuple;

        public Deliver(long eventId, long timestamp, long messageId, Node.Id from, Node.Id to,
                       MessageType messageType, @Nullable TxnId txnId, String messageClass,
                       long requestId, long replyId, int sequenceInTuple) {
            super(eventId, timestamp);
            this.messageId = messageId;
            this.from = Objects.requireNonNull(from, "from");
            this.to = Objects.requireNonNull(to, "to");
            this.messageType = messageType;
            this.txnId = txnId;
            this.messageClass = Objects.requireNonNull(messageClass, "messageClass");
            this.requestId = requestId;
            this.replyId = replyId;
            this.sequenceInTuple = sequenceInTuple;
        }

        @Override
        public TraceEventType getEventType() {
            return TraceEventType.DELIVER;
        }

        @Override
        public boolean isDependentWith(TraceEvent other) {
            // Very broad for now
            // Dependent if same nodes involved
            if (involvesNode(other.primaryNode()) || involvesNode(other.secondaryNode()))
                return true;
            // Dependent if same transaction
            if (txnId != null && txnId.equals(other.txnId()))
                return true;
            return false;
        }

        private boolean involvesNode(@Nullable Node.Id node) {
            return node != null && (from.equals(node) || to.equals(node));
        }

        @Override
        public Node.Id primaryNode() {
            return to; // destination is primary for delivery
        }

        @Override
        public Node.Id secondaryNode() {
            return from;
        }

        @Override
        public TxnId txnId() {
            return txnId;
        }

        @Override
        public String toString() {
            return String.format("Deliver{id=%d, msg=%d, %s->%s, type=%s, txn=%s, seq=%d}",
                    eventId, messageId, from, to, messageType, txnId, sequenceInTuple);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Deliver)) return false;
            Deliver deliver = (Deliver) o;
            return eventId == deliver.eventId && messageId == deliver.messageId;
        }

        @Override
        public int hashCode() {
            return Objects.hash(eventId, messageId);
        }
    }

    /**
     * Message drop event - a message was not delivered (simulated loss or crash)
     */
    public static final class Drop extends TraceEvent {
        public final long messageId;
        public final Node.Id from;
        public final Node.Id to;
        public final MessageType messageType;
        @Nullable
        public final TxnId txnId;
        public final String messageClass;
        /**
         * Sequence number within (from, to, messageType, txnId) tuple for weak matching
         */
        public final int sequenceInTuple;

        public Drop(long eventId, long timestamp, long messageId,
                    Node.Id from, Node.Id to, MessageType messageType,
                    @Nullable TxnId txnId, String messageClass, int sequenceInTuple) {
            super(eventId, timestamp);
            this.messageId = messageId;
            this.from = Objects.requireNonNull(from, "from");
            this.to = Objects.requireNonNull(to, "to");
            this.messageType = messageType;
            this.txnId = txnId;
            this.messageClass = Objects.requireNonNull(messageClass, "messageClass");
            this.sequenceInTuple = sequenceInTuple;
        }

        @Override
        public TraceEventType getEventType() {
            return TraceEventType.DROP;
        }

        @Override
        public boolean isDependentWith(TraceEvent other) {
            if (involvesNode(other.primaryNode()) || involvesNode(other.secondaryNode()))
                return true;
            if (txnId != null && txnId.equals(other.txnId()))
                return true;
            return false;
        }

        private boolean involvesNode(@Nullable Node.Id node) {
            return node != null && (from.equals(node) || to.equals(node));
        }

        @Override
        public Node.Id primaryNode() {
            return to;
        }

        @Override
        public Node.Id secondaryNode() {
            return from;
        }

        @Override
        public TxnId txnId() {
            return txnId;
        }

        @Override
        public String toString() {
            return String.format("Drop{id=%d, msg=%d, %s->%s, type=%s, txn=%s, seq=%d}",
                    eventId, messageId, from, to, messageType, txnId, sequenceInTuple);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Drop)) return false;
            Drop drop = (Drop) o;
            return eventId == drop.eventId && messageId == drop.messageId;
        }

        @Override
        public int hashCode() {
            return Objects.hash(eventId, messageId);
        }
    }

    /**
     * Node crash event - simulates crash-stop failure
     */
    public static final class Crash extends TraceEvent {
        public final Node.Id node;

        public Crash(long eventId, long timestamp, Node.Id node) {
            super(eventId, timestamp);
            this.node = Objects.requireNonNull(node, "node");
        }

        @Override
        public TraceEventType getEventType() {
            return TraceEventType.CRASH;
        }

        @Override
        public boolean isDependentWith(TraceEvent other) {
            // Crash is dependent with any event involving this node
            return node.equals(other.primaryNode()) || node.equals(other.secondaryNode());
        }

        @Override
        public Node.Id primaryNode() {
            return node;
        }

        @Override
        public String toString() {
            return String.format("Crash{id=%d, node=%s}", eventId, node);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Crash)) return false;
            Crash crash = (Crash) o;
            return eventId == crash.eventId && node.equals(crash.node);
        }

        @Override
        public int hashCode() {
            return Objects.hash(eventId, node);
        }
    }

    /**
     * Node recover event - node comes back after crash
     */
    public static final class Recover extends TraceEvent {
        public final Node.Id node;

        public Recover(long eventId, long timestamp, Node.Id node) {
            super(eventId, timestamp);
            this.node = Objects.requireNonNull(node, "node");
        }

        @Override
        public TraceEventType getEventType() {
            return TraceEventType.RECOVER;
        }

        @Override
        public boolean isDependentWith(TraceEvent other) {
            return node.equals(other.primaryNode()) || node.equals(other.secondaryNode());
        }

        @Override
        public Node.Id primaryNode() {
            return node;
        }

        @Override
        public String toString() {
            return String.format("Recover{id=%d, node=%s}", eventId, node);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Recover)) return false;
            Recover recover = (Recover) o;
            return eventId == recover.eventId && node.equals(recover.node);
        }

        @Override
        public int hashCode() {
            return Objects.hash(eventId, node);
        }
    }

    /**
     * Client operation event - a client initiated a transaction
     */
    public static final class ClientOp extends TraceEvent {
        public final long opId;
        public final Node.Id coordinator;
        @Nullable
        public final TxnId txnId;
        public final String description;

        public ClientOp(long eventId, long timestamp, long opId,
                        Node.Id coordinator, @Nullable TxnId txnId, String description) {
            super(eventId, timestamp);
            this.opId = opId;
            this.coordinator = Objects.requireNonNull(coordinator, "coordinator");
            this.txnId = txnId;
            this.description = Objects.requireNonNull(description, "description");
        }

        @Override
        public TraceEventType getEventType() {
            return TraceEventType.CLIENT_OP;
        }

        @Override
        public boolean isDependentWith(TraceEvent other) {
            if (coordinator.equals(other.primaryNode()) || coordinator.equals(other.secondaryNode()))
                return true;
            if (txnId != null && txnId.equals(other.txnId()))
                return true;
            return false;
        }

        @Override
        public Node.Id primaryNode() {
            return coordinator;
        }

        @Override
        public TxnId txnId() {
            return txnId;
        }

        @Override
        public String toString() {
            return String.format("ClientOp{id=%d, op=%d, coord=%s, txn=%s, desc=%s}",
                    eventId, opId, coordinator, txnId, description);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof ClientOp)) return false;
            ClientOp clientOp = (ClientOp) o;
            return eventId == clientOp.eventId && opId == clientOp.opId;
        }

        @Override
        public int hashCode() {
            return Objects.hash(eventId, opId);
        }
    }

    /**
     * Timer event - a timeout or scheduled task fired
     */
    public static final class Timer extends TraceEvent {
        public final long timerId;
        public final Node.Id node;
        public final String timerType;

        public Timer(long eventId, long timestamp, long timerId,
                     Node.Id node, String timerType) {
            super(eventId, timestamp);
            this.timerId = timerId;
            this.node = Objects.requireNonNull(node, "node");
            this.timerType = Objects.requireNonNull(timerType, "timerType");
        }

        @Override
        public TraceEventType getEventType() {
            return TraceEventType.TIMER;
        }

        @Override
        public boolean isDependentWith(TraceEvent other) {
            return node.equals(other.primaryNode()) || node.equals(other.secondaryNode());
        }

        @Override
        public Node.Id primaryNode() {
            return node;
        }

        @Override
        public String toString() {
            return String.format("Timer{id=%d, timer=%d, node=%s, type=%s}",
                    eventId, timerId, node, timerType);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Timer)) return false;
            Timer timer = (Timer) o;
            return eventId == timer.eventId && timerId == timer.timerId;
        }

        @Override
        public int hashCode() {
            return Objects.hash(eventId, timerId);
        }
    }
}
