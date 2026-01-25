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

import accord.local.Node;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;


public class TraceEventTest {
    private TraceRecorder recorder;
    private Node.Id node1;
    private Node.Id node2;
    private Node.Id node3;

    @BeforeEach
    void setUp() {
        recorder = new TraceRecorder(12345L, 3, 100, "test-1.0");
        node1 = new Node.Id(1);
        node2 = new Node.Id(2);
        node3 = new Node.Id(3);
    }

    @Test
    void testRecordDeliverEvent() {
        long msgId = recorder.allocateMessageId();
        TraceEvent.Deliver event = recorder.recordDeliver(
                msgId, node1, node2, null, 1L, -1L
        );

        assertEquals(1, recorder.eventCount());
        assertEquals(TraceEvent.TraceEventType.DELIVER, event.getEventType());
        assertEquals(node1, event.from);
        assertEquals(node2, event.to);
        assertEquals(msgId, event.messageId);
    }

    @Test
    void testRecordCrashEvent() {
        TraceEvent.Crash event = recorder.recordCrash(node1);

        assertEquals(1, recorder.eventCount());
        assertEquals(TraceEvent.TraceEventType.CRASH, event.getEventType());
        assertEquals(node1, event.node);
    }

    @Test
    void testRecordRecoverEvent() {
        TraceEvent.Recover event = recorder.recordRecover(node1);

        assertEquals(1, recorder.eventCount());
        assertEquals(TraceEvent.TraceEventType.RECOVER, event.getEventType());
        assertEquals(node1, event.node);
    }

    @Test
    void testEventDependency_SameNode() {
        // Events involving the same node are dependent
        TraceEvent.Deliver e1 = new TraceEvent.Deliver(1, 1, 100, node1, node2, null, null, "TestMsg", 1, -1, 0);
        TraceEvent.Deliver e2 = new TraceEvent.Deliver(2, 2, 101, node2, node3, null, null, "TestMsg", 2, -1, 0);

        // e1 involves node1->node2, e2 involves node2->node3
        // They share node2, so they are dependent
        assertTrue(e1.isDependentWith(e2));
        assertTrue(e2.isDependentWith(e1));
    }

    @Test
    void testEventDependency_DisjointNodes() {
        Node.Id node4 = new Node.Id(4);

        TraceEvent.Deliver e1 = new TraceEvent.Deliver(1, 1, 100, node1, node2, null, null, "TestMsg", 1, -1, 0);
        TraceEvent.Deliver e2 = new TraceEvent.Deliver(2, 2, 101, node3, node4, null, null, "TestMsg", 2, -1, 0);

        assertFalse(e1.isDependentWith(e2));
        assertFalse(e2.isDependentWith(e1));
    }

    @Test
    void testEventDependency_CrashWithMessage() {
        // Crash event is dependent with any message involving that node
        TraceEvent.Crash crash = new TraceEvent.Crash(1, 1, node2);
        TraceEvent.Deliver deliver = new TraceEvent.Deliver(
                2, 2, 100, node1, node2, null, null, "TestMsg", 1, -1, 0
        );

        assertTrue(crash.isDependentWith(deliver));
        assertTrue(deliver.isDependentWith(crash));
    }

    @Test
    void testTraceSwappableEvents() {
        Trace trace = recorder.trace();
        Node.Id node4 = new Node.Id(4);

        // Add two independent events
        recorder.recordDeliver(1, node1, node2, null, 1, -1);
        recorder.recordDeliver(2, node3, node4, null, 2, -1);

        // They should be swappable (independent)
        assertTrue(trace.areIndependent(0, 1));

        var swappable = trace.findSwappablePairs();
        assertEquals(1, swappable.size());
        assertArrayEquals(new int[]{0, 1}, swappable.get(0));
    }

    @Test
    void testTraceNonSwappableEvents() {
        Trace trace = recorder.trace();

        // Add two dependent events (same destination node)
        recorder.recordDeliver(1, node1, node2, null, 1, -1);
        recorder.recordDeliver(2, node3, node2, null, 2, -1);

        // They should NOT be swappable (dependent - both deliver to node2)
        assertFalse(trace.areIndependent(0, 1));

        var swappable = trace.findSwappablePairs();
        assertTrue(swappable.isEmpty());
    }

    @Test
    void testTracePrefix() {
        recorder.recordDeliver(1, node1, node2, null, 1, -1);
        recorder.recordCrash(node3);
        recorder.recordDeliver(2, node2, node3, null, 2, -1);

        Trace prefix = recorder.trace().prefix(2);
        assertEquals(2, prefix.size());
        assertEquals(TraceEvent.TraceEventType.DELIVER, prefix.get(0).getEventType());
        assertEquals(TraceEvent.TraceEventType.CRASH, prefix.get(1).getEventType());
    }

    @Test
    void testEventFiltering() {
        recorder.recordDeliver(1, node1, node2, null, 1, -1);
        recorder.recordCrash(node2);
        recorder.recordDeliver(2, node2, node3, null, 2, -1);
        recorder.recordRecover(node2);

        Trace trace = recorder.trace();

        assertEquals(2, trace.countByKind(TraceEvent.TraceEventType.DELIVER));
        assertEquals(1, trace.countByKind(TraceEvent.TraceEventType.CRASH));
        assertEquals(1, trace.countByKind(TraceEvent.TraceEventType.RECOVER));

        var node2Events = trace.eventsInvolvingNode(node2);
        assertEquals(4, node2Events.size()); // All events involve node2
    }
}

