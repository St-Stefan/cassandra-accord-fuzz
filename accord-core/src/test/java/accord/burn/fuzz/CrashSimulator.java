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

//Just pasted that license from another file, hope it's fine
package accord.burn.fuzz;

import accord.local.Node;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class CrashSimulator {
    private final Set<Node.Id> crashedNodes = ConcurrentHashMap.newKeySet();

    public void crash(Node.Id nodeId) {
        crashedNodes.add(nodeId);
    }

    public boolean isCrashed(Node.Id nodeId) {
        return crashedNodes.contains(nodeId);
    }

    public boolean shouldDeliver(Node.Id from, Node.Id to) {
        return !crashedNodes.contains(from) && !crashedNodes.contains(to);
    }

    public void recovered(Node.Id nodeId) {
        crashedNodes.remove(nodeId);
    }

    public Set<Node.Id> getCrashedNodes() {
        return Collections.unmodifiableSet(crashedNodes);
    }

    public void reset() {
        crashedNodes.clear();
    }
}
