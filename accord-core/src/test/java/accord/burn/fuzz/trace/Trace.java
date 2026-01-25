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
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import accord.local.Node;
import accord.primitives.TxnId;

/**
 * A trace is a complete execution history of the system.
 * For Mazurkiewicz trace equivalence, two traces are equivalent if they
 * only differ in the ordering of independent events.
 */
public class Trace implements Iterable<TraceEvent> {
    public record Header(long seed, int nodeCount, int operationCount, String version, long createdAt) {
        public Header(long seed, int nodeCount, int operationCount, String version) {
            this(seed, nodeCount, operationCount, Objects.requireNonNull(version, "version"), System.currentTimeMillis());
        }

        public Header(long seed, int nodeCount, int operationCount, String version, long createdAt) {
            this.seed = seed;
            this.nodeCount = nodeCount;
            this.operationCount = operationCount;
            this.version = Objects.requireNonNull(version, "version");
            this.createdAt = createdAt;
        }

        @Override
        public String toString() {
            return String.format("Header{seed=%d, nodes=%d, ops=%d, version=%s}",
                    seed, nodeCount, operationCount, version);
        }
    }

    private final Header header;
    private final List<TraceEvent> events;
    private final Set<Long> observedStates;

    public Trace(Header header) {
        this.header = Objects.requireNonNull(header, "header");
        this.events = new ArrayList<>();
        this.observedStates = new HashSet<>();
    }

    public Trace(Header header, List<TraceEvent> events) {
        this.header = Objects.requireNonNull(header, "header");
        this.events = new ArrayList<>(events);
        this.observedStates = new HashSet<>();
    }

    public Header header() {
        return header;
    }

    /**
     * Add an event to the trace
     */
    public void add(TraceEvent event) {
        events.add(Objects.requireNonNull(event, "event"));
    }

    /**
     * Record a state fingerprint observed during execution
     */
    public void recordState(long stateFingerprint) {
        observedStates.add(stateFingerprint);
    }

    public List<TraceEvent> events() {
        return Collections.unmodifiableList(events);
    }

    public int size() {
        return events.size();
    }

    public boolean isEmpty() {
        return events.isEmpty();
    }

    public TraceEvent get(int index) {
        return events.get(index);
    }

    public int uniqueStateCount() {
        return observedStates.size();
    }

    @Override
    public Iterator<TraceEvent> iterator() {
        return events.iterator();
    }

    // ========== Event Querying ==========

    public List<TraceEvent> eventsInvolvingNode(Node.Id node) {
        return events.stream()
                .filter(e -> node.equals(e.primaryNode()) || node.equals(e.secondaryNode()))
                .collect(Collectors.toList());
    }

    /**
     * Get all events for a specific transaction
     */
    public List<TraceEvent> eventsForTransaction(TxnId txnId) {
        return events.stream()
                .filter(e -> txnId.equals(e.txnId()))
                .collect(Collectors.toList());
    }

    /**
     * Get all events of a specific kind
     */
    public List<TraceEvent> eventsOfKind(TraceEvent.TraceEventType traceEventType) {
        return events.stream()
                .filter(e -> e.getEventType() == traceEventType)
                .collect(Collectors.toList());
    }

    public int countByKind(TraceEvent.TraceEventType traceEventType) {
        return (int) events.stream().filter(e -> e.getEventType() == traceEventType).count();
    }


    /**
     * Check if two events at given indices are independent
     */
    public boolean areIndependent(int idx1, int idx2) {
        if (idx1 < 0 || idx1 >= events.size() || idx2 < 0 || idx2 >= events.size())
            return false;
        return !events.get(idx1).isDependentWith(events.get(idx2));
    }

    /**
     * Find all pairs of adjacent events that can be swapped (independent)
     */
    public List<int[]> findSwappablePairs() {
        List<int[]> pairs = new ArrayList<>();
        for (int i = 0; i < events.size() - 1; i++) {
            if (areIndependent(i, i + 1))
                pairs.add(new int[]{i, i + 1});
        }
        return pairs;
    }

    public Trace swapEvents(int idx1, int idx2) {
        if (!areIndependent(idx1, idx2))
            throw new IllegalArgumentException("Cannot swap dependent events:" + idx1 + " and " + idx2);

        List<TraceEvent> newEvents = new ArrayList<>(events);
        TraceEvent temp = newEvents.get(idx1);
        newEvents.set(idx1, newEvents.get(idx2));
        newEvents.set(idx2, temp);
        return new Trace(header, newEvents);
    }

    // Fuzzing-specific methods

    public Trace copy() {
        return new Trace(header, new ArrayList<>(events));
    }

    public Trace prefix(int endIndex) {
        return new Trace(header, events.subList(0, endIndex));
    }

    public Trace suffix(int startIndex) {
        return new Trace(header, events.subList(startIndex, events.size()));
    }


    public String toFullString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Trace{").append(header).append(", events=[\n");
        for (int i = 0; i < events.size(); i++) {
            sb.append("  ").append(i).append(": ").append(events.get(i)).append("\n");
        }
        sb.append("], states=").append(observedStates.size()).append("}");
        return sb.toString();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Trace{").append(header).append(", events=[\n");
        for (int i = 0; i < Math.min(events.size(), 10); i++) {
            sb.append("  ").append(i).append(": ").append(events.get(i)).append("\n");
        }
        if (events.size() > 10)
            sb.append("  ... (").append(events.size() - 10).append(" more)\n");
        sb.append("], states=").append(observedStates.size()).append("}");
        return sb.toString();
    }
}
