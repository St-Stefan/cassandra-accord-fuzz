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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import accord.burn.fuzz.trace.Trace;
import accord.burn.fuzz.trace.TraceEvent;
import accord.primitives.TxnId;

/**
 * Assigns each {@link TxnId} in a trace a small run-independent integer, so predicate state can
 * be hashed and compared across seeds/mutants instead of on the raw {@code TxnId} (whose
 * epoch/hlc are seed-dependent and never match across runs).
 * <p>
 * This is deliberately the same pass as {@link Trace#toTlaJson}'s Pass 1: group distinct
 * {@code TxnId}s by the coordinator that sent their {@code PreAccept} (first-appearance order
 * within each coordinator), sort coordinators by node id, then assign sequential ids coordinator
 * by coordinator. Mirroring it - rather than deriving identity a different way (e.g. from
 * {@code TxnId.node}) - means the id a transaction gets here matches the {@code "id"} already
 * written into the TLA JSON export for the same trace.
 */
public final class TxnNormalizer {
    private TxnNormalizer() {}

    public static Map<TxnId, Integer> normalize(Trace trace) {
        Map<Integer, List<TxnId>> coordTxnIds = new LinkedHashMap<>();
        for (TraceEvent event : trace.events()) {
            if (!(event instanceof TraceEvent.Deliver))
                continue;
            TraceEvent.Deliver d = (TraceEvent.Deliver) event;
            if (!"PreAccept".equals(d.messageClass) || d.txnId == null || d.from.id <= 0)
                continue;
            List<TxnId> list = coordTxnIds.computeIfAbsent(d.from.id, k -> new ArrayList<>());
            if (!list.contains(d.txnId))
                list.add(d.txnId);
        }

        List<Integer> sortedCoords = new ArrayList<>(coordTxnIds.keySet());
        Collections.sort(sortedCoords);

        Map<TxnId, Integer> txnToId = new LinkedHashMap<>();
        int nextId = 1;
        for (int coord : sortedCoords)
            for (TxnId txnId : coordTxnIds.get(coord))
                txnToId.put(txnId, nextId++);

        return txnToId;
    }
}
