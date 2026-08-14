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
# Launches the three predicate-guided variants side by side, each ~16h/seed sequentially within
# its seed set. They share whatever TLC server (if any) is listening at localhost:2023.
#
#   ./scripts/run-predicate-variants.sh                # all 3 variants
#   ./scripts/run-predicate-variants.sh --nodes=5       # all 3 variants at 5 nodes
#   ./scripts/run-predicate-variants.sh --set=2         # just seed set 2
#   ./scripts/run-predicate-variants.sh --variant=reached --nodes=9 --set=1
#
# Variants:
#   full       - predicateMatrix           full history,          EXTENT classifier,   reseed off
#   reached    - predicateReachedMatrix    full history,          REACHED_COMPLETED,   reseed off
#   compressed - predicateCompressedMatrix CURRENT_STAGE_ONLY,    EXTENT classifier,   reseed every 7000 iters
#
# Logs land in build/fuzz-logs/<variant>_n<nodes>_set<N>.log (see run-fuzz-matrix.sh for why they
# live under build/). Fuzzer output itself lands under accord-core/build/test-traces/fuzzer/.
set -euo pipefail

cd "$(dirname "$0")/.."

VARIANT_FILTER=""
NODES_FILTER=""
SET_FILTER=""
for arg in "$@"; do
    case "$arg" in
        --variant=*) VARIANT_FILTER="${arg#--variant=}" ;;
        --nodes=*)   NODES_FILTER="${arg#--nodes=}" ;;
        --set=*)     SET_FILTER="${arg#--set=}" ;;
        *) echo "Unknown argument: $arg (expected --variant=NAME, --nodes=N, and/or --set=N)" >&2; exit 1 ;;
    esac
done

case "$VARIANT_FILTER" in
    ""|full|reached|compressed) ;;
    *) echo "Unknown --variant='$VARIANT_FILTER' (expected full, reached, or compressed)" >&2; exit 1 ;;
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
    local variant="$1" method="$2" nodes="$3" set="$4"
    [[ -n "$VARIANT_FILTER" && "$variant" != "$VARIANT_FILTER" ]] && return
    [[ -n "$NODES_FILTER"   && "$nodes"   != "$NODES_FILTER"   ]] && return
    [[ -n "$SET_FILTER"     && "$set"     != "$SET_FILTER"     ]] && return
    local log="$LOGS/${variant}_n${nodes}_set${set}.log"
    nohup ./gradlew --no-daemon :accord-core:test --tests "accord.burn.fuzz.FuzzerTest.${method}" \
        -PfuzzNodes="$nodes" -PfuzzSet="$set" > "$log" 2>&1 &
    echo "launched $variant nodes=$nodes set=$set -> $log (pid $!)"
    launched=$((launched + 1))
}

launch full       predicateMatrix           5 1
launch full       predicateMatrix           5 2
launch full       predicateMatrix           7 1
launch full       predicateMatrix           7 2
launch full       predicateMatrix           9 1
launch full       predicateMatrix           9 2

launch reached    predicateReachedMatrix    5 1
launch reached    predicateReachedMatrix    5 2
launch reached    predicateReachedMatrix    7 1
launch reached    predicateReachedMatrix    7 2
launch reached    predicateReachedMatrix    9 1
launch reached    predicateReachedMatrix    9 2

launch compressed predicateCompressedMatrix 5 1
launch compressed predicateCompressedMatrix 5 2
launch compressed predicateCompressedMatrix 7 1
launch compressed predicateCompressedMatrix 7 2
launch compressed predicateCompressedMatrix 9 1
launch compressed predicateCompressedMatrix 9 2

if [[ $launched -eq 0 ]]; then
    echo "No combo matched --variant='$VARIANT_FILTER' --nodes='$NODES_FILTER' --set='$SET_FILTER'" >&2
    exit 1
fi
echo "launched $launched combo(s); tail -f $LOGS/*.log to follow, jobs -l to see PIDs"