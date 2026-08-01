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

import java.util.HashSet;
import java.util.Set;

import accord.burn.fuzz.trace.Trace;

/**
 * Predicate-based counterpart to {@code accord.burn.fuzz.TlcGuider}, deliberately matching its
 * shape ({@link #check(Trace)} / {@link #totalSeenStates()}) so it can drop into {@code
 * Fuzzer.run()} the same way. Unlike {@code TlcGuider}, this has no external dependency (no TLC
 * server round trip) - it's a pure function of the already-recorded {@link Trace}, so there is no
 * failure mode to degrade gracefully from.
 * <p>
 * Each call to {@link #check} replays the given trace through a fresh {@link PredicateStateMachine}
 * (so state from one trace never leaks into another's replay) and folds its visited joint states
 * into a single cross-execution {@code totalSeenStates} set, returning how many of them were new.
 */
public class PredicateGuider
{
    private final StageClassifier classifier;
    private final HistoryMode historyMode;
    private final Set<String> totalSeenStates = new HashSet<>();

    /** Defaults to {@link HistoryMode#FULL_HISTORY}, the original behavior. */
    public PredicateGuider(StageClassifier classifier)
    {
        this(classifier, HistoryMode.FULL_HISTORY);
    }

    public PredicateGuider(StageClassifier classifier, HistoryMode historyMode)
    {
        this.classifier = classifier;
        this.historyMode = historyMode;
    }

    /**
     * Replay {@code trace} and return the number of newly discovered joint predicate states.
     */
    public int check(Trace trace)
    {
        PredicateStateMachine machine = PredicateStateMachine.replay(trace, classifier, historyMode);
        int newCount = 0;
        for (String state : machine.visitedStates())
            if (totalSeenStates.add(state))
                newCount++;
        return newCount;
    }

    public int totalSeenStates()
    {
        return totalSeenStates.size();
    }
}
