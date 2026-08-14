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
# Launches the full fuzzer matrix: 4 modes x 3 node counts x 2 seed sets (5 seeds each),
# each seed running ~16h sequentially within its set (~80h / ~3.3 days per combo). Combos run in parallel
# as separate backgrounded processes on this one box, sharing whatever TLC server (if any) is
# listening at localhost:2023.
#
# Comment out any line below to skip that combo, or filter from the command line instead:
#   ./scripts/run-fuzz-matrix.sh                          # all 24 combos
#   ./scripts/run-fuzz-matrix.sh --mode=predicate         # predicate, all node counts, both sets
#   ./scripts/run-fuzz-matrix.sh --nodes=7                # all 4 modes at 7 nodes, both sets
#   ./scripts/run-fuzz-matrix.sh --set=1                  # just seed set 1, everything else
#   ./scripts/run-fuzz-matrix.sh --mode=modelfuzz --nodes=7 --set=2   # just that one combo
#
# Logs land in build/fuzz-logs/<mode>_n<nodes>_set<N>.log (under build/ so Apache Rat's
# license-header audit - a dependency of the test task - doesn't scan and fail on plain-text log
# files with no header). Fuzzer output itself (traces, coverage csv, etc.) lands under
# accord-core/build/test-traces/fuzzer/, named by SessionNaming so parallel combos never collide
# and `ls` sorts chronologically.
set -euo pipefail

cd "$(dirname "$0")/.."

MODE_FILTER=""
NODES_FILTER=""
SET_FILTER=""
for arg in "$@"; do
    case "$arg" in
        --mode=*)  MODE_FILTER="${arg#--mode=}" ;;
        --nodes=*) NODES_FILTER="${arg#--nodes=}" ;;
        --set=*)   SET_FILTER="${arg#--set=}" ;;
        *) echo "Unknown argument: $arg (expected --mode=NAME, --nodes=N, and/or --set=N)" >&2; exit 1 ;;
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
case "$SET_FILTER" in
    ""|1|2) ;;
    *) echo "Unknown --set='$SET_FILTER' (expected 1 or 2)" >&2; exit 1 ;;
esac

mkdir -p build/fuzz-logs
LOGS=build/fuzz-logs
launched=0

# Build once up front so the parallel invocations below don't race each other compiling.
./gradlew :accord-core:testClasses

launch() {
    local mode="$1" method="$2" nodes="$3" set="$4"
    [[ -n "$MODE_FILTER"  && "$mode"  != "$MODE_FILTER"  ]] && return
    [[ -n "$NODES_FILTER" && "$nodes" != "$NODES_FILTER" ]] && return
    [[ -n "$SET_FILTER"   && "$set"   != "$SET_FILTER"   ]] && return
    local log="$LOGS/${mode}_n${nodes}_set${set}.log"
    nohup ./gradlew --no-daemon :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.${method}" \
        -PfuzzNodes="$nodes" -PfuzzSet="$set" > "$log" 2>&1 &
    echo "launched $mode nodes=$nodes set=$set -> $log (pid $!)"
    launched=$((launched + 1))
}

launch modelfuzz      modelfuzzMatrix      5 1
launch modelfuzz      modelfuzzMatrix      5 2
launch modelfuzz      modelfuzzMatrix      7 1
launch modelfuzz      modelfuzzMatrix      7 2
launch modelfuzz      modelfuzzMatrix      9 1
launch modelfuzz      modelfuzzMatrix      9 2

launch random         randomMatrix         5 1
launch random         randomMatrix         5 2
launch random         randomMatrix         7 1
launch random         randomMatrix         7 2
launch random         randomMatrix         9 1
launch random         randomMatrix         9 2

launch randomschedule randomScheduleMatrix 5 1
launch randomschedule randomScheduleMatrix 5 2
launch randomschedule randomScheduleMatrix 7 1
launch randomschedule randomScheduleMatrix 7 2
launch randomschedule randomScheduleMatrix 9 1
launch randomschedule randomScheduleMatrix 9 2

launch predicate      predicateMatrix      5 1
launch predicate      predicateMatrix      5 2
launch predicate      predicateMatrix      7 1
launch predicate      predicateMatrix      7 2
launch predicate      predicateMatrix      9 1
launch predicate      predicateMatrix      9 2

if [[ $launched -eq 0 ]]; then
    echo "No combo matched --mode='$MODE_FILTER' --nodes='$NODES_FILTER' --set='$SET_FILTER'" >&2
    exit 1
fi
echo "launched $launched combo(s); tail -f $LOGS/*.log to follow, jobs -l to see PIDs"
