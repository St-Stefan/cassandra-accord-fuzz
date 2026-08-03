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

import java.util.Map;

import org.junit.jupiter.api.Test;

import accord.burn.fuzz.trace.Trace;
import accord.burn.fuzz.trace.TraceEvent;
import accord.local.Node;
import accord.messages.MessageType.StandardMessage;
import accord.primitives.Routable.Domain;
import accord.primitives.Txn.Kind;
import accord.primitives.TxnId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class TxnNormalizerTest {

    private static Node.Id node(int i) { return new Node.Id(i); }

    private static TxnId txn(int coordinatorId, int hlc)
    {
        return new TxnId(1, hlc, Kind.Write, Domain.Key, node(coordinatorId));
    }

    private static void preAccept(Trace trace, long eventId, Node.Id coordinator, Node.Id to, TxnId txnId)
    {
        trace.add(new TraceEvent.Deliver(eventId, eventId, eventId, coordinator, to,
                StandardMessage.PRE_ACCEPT_REQ, txnId, "PreAccept", eventId, Integer.MIN_VALUE, 0));
    }

    /**
     * Two coordinators (2 and 5, so id order != submission order), coordinator 5 appears first in
     * the trace but must still get the higher ids once sorted by node id.
     */
    @Test
    void ordersByCoordinatorNodeIdThenFirstAppearance()
    {
        TxnId c5t1 = txn(5, 1);
        TxnId c5t2 = txn(5, 2);
        TxnId c2t1 = txn(2, 1);

        Trace trace = new Trace(new Trace.Header(1L, 7, 3, "test-1.0"));
        long e = 1;
        preAccept(trace, e++, node(5), node(1), c5t1);
        preAccept(trace, e++, node(5), node(1), c5t2);
        preAccept(trace, e++, node(2), node(1), c2t1);
        // a second PreAccept for c5t1 to a different node must not get counted as a new txn
        preAccept(trace, e++, node(5), node(3), c5t1);

        Map<TxnId, Integer> ids = TxnNormalizer.normalize(trace);

        assertEquals(1, ids.get(c2t1));  // coordinator 2 sorts before coordinator 5
        assertEquals(2, ids.get(c5t1));  // then coordinator 5's txns in first-appearance order
        assertEquals(3, ids.get(c5t2));
    }

    @Test
    void ignoresNonPreAcceptAndClientOriginatedEvents()
    {
        TxnId t = txn(1, 1);
        Trace trace = new Trace(new Trace.Header(2L, 7, 1, "test-1.0"));

        // client submit (from.id == -1) must be ignored, not treated as a coordinator
        trace.add(new TraceEvent.Deliver(1, 1, 1, node(-1), node(1),
                null, t, "Submit", 1, Integer.MIN_VALUE, 0));
        // a non-PreAccept request for the same txn must not create an entry on its own
        trace.add(new TraceEvent.Deliver(2, 2, 2, node(1), node(2),
                StandardMessage.ACCEPT_REQ, t, "Accept", 2, Integer.MIN_VALUE, 0));

        Map<TxnId, Integer> ids = TxnNormalizer.normalize(trace);

        assertNull(ids.get(t));
    }
}
