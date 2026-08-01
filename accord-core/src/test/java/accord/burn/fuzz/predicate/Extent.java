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

/**
 * How much of the node set a stage-count reached, given the configured quorum size {@code q}
 * and node count {@code n}. Named {@code Extent} (not {@code Cardinality}) to avoid colliding
 * with {@link accord.primitives.TxnId.Cardinality}, an unrelated concept.
 */
public enum Extent
{
    NONE, SUBSET, QUORUM, ALL;

    public static Extent of(int count, int quorum, int n)
    {
        if (count <= 0) return NONE;
        if (count >= n) return ALL;
        if (count >= quorum) return QUORUM;
        return SUBSET;
    }
}
