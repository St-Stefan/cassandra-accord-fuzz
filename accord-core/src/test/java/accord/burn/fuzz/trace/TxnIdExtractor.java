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

package accord.burn.fuzz.trace;

import java.lang.reflect.Field;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nullable;

import accord.messages.Message;
import accord.primitives.TxnId;

/**
 * Utility to extract TxnId from various message types.
 * <p>
 * Most Accord protocol messages carry a TxnId, but they don't share
 * a common interface for accessing it. This utility uses reflection
 * as a fallback when the message type is not known.
 */
public class TxnIdExtractor {
    /**
     * Cache of TxnId field lookups by class
     */
    private static final ConcurrentHashMap<Class<?>, Field> txnIdFieldCache = new ConcurrentHashMap<>();

    /**
     * Sentinel to indicate no TxnId field exists
     */
    private static final Field NO_FIELD;

    static {
        try {
            NO_FIELD = TxnIdExtractor.class.getDeclaredField("NO_FIELD");
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Extract TxnId from a message, if present.
     *
     * @param message the message to extract from
     * @return the TxnId, or null if not present
     */
    @Nullable
    public static TxnId extract(@Nullable Message message) {
        if (message == null)
            return null;

        // Try reflection-based extraction
        return extractViaReflection(message);
    }

    @Nullable
    private static TxnId extractViaReflection(Object message) {
        Class<?> clazz = message.getClass();
        Field field = txnIdFieldCache.computeIfAbsent(clazz, TxnIdExtractor::findTxnIdField);

        if (field == NO_FIELD)
            return null;

        try {
            return (TxnId) field.get(message);
        } catch (IllegalAccessException e) {
            return null;
        }
    }

    private static Field findTxnIdField(Class<?> clazz) {
        // Walk up the class hierarchy looking for a txnId field
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            try {
                Field field = current.getDeclaredField("txnId");
                if (TxnId.class.isAssignableFrom(field.getType())) {
                    field.setAccessible(true);
                    return field;
                }
            } catch (NoSuchFieldException ignored) {
                // Try parent class
            }
            current = current.getSuperclass();
        }
        return NO_FIELD;
    }

    /**
     * Check if a message type is known to carry a TxnId
     */
    public static boolean hasTxnId(Class<?> messageClass) {
        Field field = txnIdFieldCache.computeIfAbsent(messageClass, TxnIdExtractor::findTxnIdField);
        return field != NO_FIELD;
    }
}

