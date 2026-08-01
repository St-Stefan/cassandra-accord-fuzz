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

import accord.messages.MessageType;

/**
 * Maps a {@link MessageType} to the protocol stage it belongs to, mechanically, from its
 * name alone (no per-message-type knowledge). {@code PRE_ACCEPT_REQ} / {@code PRE_ACCEPT_RSP}
 * both map to stage {@code "PRE_ACCEPT"}.
 * <p>
 * Two message types don't name their own stage: {@code SIMPLE_RSP} and {@code FAILURE_RSP} are
 * generic acknowledgements reused across several request stages (e.g. {@code COMMIT_REQ},
 * {@code NOT_ACCEPT_REQ}). Callers must resolve those via the request they answer - see
 * {@link #namesOwnStage(MessageType)}.
 */
public final class StageExtractor
{
    private static final String REQ_SUFFIX = "_REQ";
    private static final String RSP_SUFFIX = "_RSP";

    private StageExtractor() {}

    // MessageType is an interface; StandardMessage (the sole implementor in this codebase) is
    // the enum that actually carries a name. Casting rather than requiring callers to downcast.
    private static String nameOf(MessageType type)
    {
        return ((Enum<?>) type).name();
    }

    public static boolean isRequest(MessageType type)
    {
        return nameOf(type).endsWith(REQ_SUFFIX);
    }

    public static boolean isReply(MessageType type)
    {
        return nameOf(type).endsWith(RSP_SUFFIX);
    }

    /**
     * False for the generic replies ({@code SIMPLE_RSP}, {@code FAILURE_RSP}) whose name carries
     * no stage information; true for every other request/reply type.
     */
    public static boolean namesOwnStage(MessageType type)
    {
        String name = nameOf(type);
        return !name.equals("SIMPLE_RSP") && !name.equals("FAILURE_RSP");
    }

    /**
     * The stage this message type belongs to, e.g. {@code PRE_ACCEPT_REQ} -> {@code "PRE_ACCEPT"}.
     * Must not be called on a message type for which {@link #namesOwnStage(MessageType)} is false.
     */
    public static String stageOf(MessageType type)
    {
        String name = nameOf(type);
        if (name.endsWith(REQ_SUFFIX))
            return name.substring(0, name.length() - REQ_SUFFIX.length());
        if (name.endsWith(RSP_SUFFIX))
            return name.substring(0, name.length() - RSP_SUFFIX.length());
        return name;
    }
}
