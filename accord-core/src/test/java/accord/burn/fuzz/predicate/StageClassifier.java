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

import java.util.List;

/**
 * Collapses one stage's {@code (sent, acked)} counts (as produced by {@link PredicateTraceWalker})
 * into a small, hashable abstract value. This is the only thing that differs between abstraction
 * levels - {@link PredicateTraceWalker} runs exactly once regardless of which classifier is used.
 */
@FunctionalInterface
public interface StageClassifier
{
    Object classify(int sent, int acked, int quorum, int n);

    /** Level 2 - four-way cardinality class per direction, e.g. {@code [ALL, QUORUM]}. */
    StageClassifier EXTENT = (sent, acked, quorum, n) ->
        List.of(Extent.of(sent, quorum, n), Extent.of(acked, quorum, n));

    /**
     * Level 3 - reached (sent >= 1) / completed (sent >= quorum AND acked >= quorum), e.g.
     * {@code [true, false]}. {@code acked <= sent} always holds ({@link
     * accord.burn.fuzz.predicate.PredicateTraceWalker} only ever records an ack by correlating it
     * back to a request it already recorded as sent), so {@code acked >= quorum} alone already
     * implies {@code sent >= quorum} in a well-formed trace - the explicit {@code sent >= quorum}
     * check doesn't change any classification today, but means a future correlation bug that broke
     * that invariant (this codebase has had two: see {@code PredicateTraceWalker}'s and {@code
     * TraceRecorder}'s requestId node-scoping fixes) would surface as "not completed" rather than
     * silently reporting completion off inconsistent data.
     */
    StageClassifier REACHED_COMPLETED = (sent, acked, quorum, n) ->
        List.of(sent >= 1, sent >= quorum && acked >= quorum);
}
