#!/usr/bin/env bash
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Launches the full fuzzer matrix: 4 modes x 3 node counts, each running 10 seeds
# sequentially (~24h/seed, ~10 days/combo) inside one Gradle test invocation.
# Combos run in parallel as separate backgrounded processes on this one box, sharing
# whatever TLC server (if any) is listening at localhost:2023.
#
# Comment out any line below to skip that combo, or filter from the command line instead:
#   ./scripts/run-fuzz-matrix.sh                          # all 12 combos
#   ./scripts/run-fuzz-matrix.sh --mode=predicate         # predicate at all 3 node counts
#   ./scripts/run-fuzz-matrix.sh --nodes=7                # all 4 modes at 7 nodes
#   ./scripts/run-fuzz-matrix.sh --mode=modelfuzz --nodes=7   # just that one combo
#
# Logs land in build/fuzz-logs/<mode>_n<nodes>.log (under build/ so Apache Rat's license-header
# audit - a dependency of the test task - doesn't scan and fail on plain-text log files with no
# header). Fuzzer output itself (traces, coverage csv, etc.) lands under
# accord-core/build/test-traces/fuzzer/, named by SessionNaming so parallel combos never collide
# and `ls` sorts chronologically.
set -euo pipefail

cd "$(dirname "$0")/.."

MODE_FILTER=""
NODES_FILTER=""
for arg in "$@"; do
    case "$arg" in
        --mode=*)  MODE_FILTER="${arg#--mode=}" ;;
        --nodes=*) NODES_FILTER="${arg#--nodes=}" ;;
        *) echo "Unknown argument: $arg (expected --mode=NAME and/or --nodes=N)" >&2; exit 1 ;;
    esac
done

case "$MODE_FILTER" in
    ""|modelfuzz|random|randomschedule|predicate) ;;
    *) echo "Unknown --mode='$MODE_FILTER' (expected modelfuzz, random, randomschedule, or predicate)" >&2; exit 1 ;;
esac
case "$NODES_FILTER" in
    ""|5|7|9) ;;
    *) echo "Unknown --nodes='$NODES_FILTER' (expected 5, 7, or 9)" >&2; exit 1 ;;
esac

mkdir -p build/fuzz-logs
LOGS=build/fuzz-logs
launched=0

# Build once up front so the parallel invocations below don't race each other compiling.
./gradlew :accord-core:testClasses

launch() {
    local mode="$1" method="$2" nodes="$3"
    [[ -n "$MODE_FILTER"  && "$mode"  != "$MODE_FILTER"  ]] && return
    [[ -n "$NODES_FILTER" && "$nodes" != "$NODES_FILTER" ]] && return
    local log="$LOGS/${mode}_n${nodes}.log"
    nohup ./gradlew --no-daemon :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.${method}" \
        -PfuzzNodes="$nodes" > "$log" 2>&1 &
    echo "launched $mode nodes=$nodes -> $log (pid $!)"
    launched=$((launched + 1))
}

launch modelfuzz      modelfuzzMatrix      5
launch modelfuzz      modelfuzzMatrix      7
launch modelfuzz      modelfuzzMatrix      9

launch random         randomMatrix         5
launch random         randomMatrix         7
launch random         randomMatrix         9

launch randomschedule randomScheduleMatrix 5
launch randomschedule randomScheduleMatrix 7
launch randomschedule randomScheduleMatrix 9

launch predicate      predicateMatrix      5
launch predicate      predicateMatrix      7
launch predicate      predicateMatrix      9

if [[ $launched -eq 0 ]]; then
    echo "No combo matched --mode='$MODE_FILTER' --nodes='$NODES_FILTER'" >&2
    exit 1
fi
echo "launched $launched combo(s); tail -f $LOGS/*.log to follow, jobs -l to see PIDs"
