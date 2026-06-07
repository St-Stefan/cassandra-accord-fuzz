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

import javax.annotation.Nullable;

import accord.messages.Accept;
import accord.messages.Apply;
import accord.messages.Commit;
import accord.messages.Message;
import accord.messages.PreAccept;
import accord.messages.StableThenRead;
import accord.primitives.TxnId;

final class MessageTraceJson {
    private MessageTraceJson() {}

    static String toDeliverActionJson(int from, int to, String messageClass, String fieldsJson) {
        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        sb.append("\"name\":\"Deliver\",");
        sb.append("\"params\":{");
        sb.append("\"from\":").append(from).append(',');
        sb.append("\"to\":").append(to).append(',');
        sb.append("\"type\":\"").append(escape(tlaMessageType(messageClass))).append('"');
        appendParamsFromFieldsJson(sb, fieldsJson);
        sb.append("}}");
        return sb.toString();
    }

    private static String tlaMessageType(String messageClass) {
        return messageClass == null || "null".equals(messageClass) ? "TypeUnknown" : "Type" + messageClass;
    }

    // Java simple class name → TLA+ Deliver type for FullSpecActionMapper.
    // fieldsJson is the stored message JSON, used to distinguish Commit from Stable
    // (both use the same Java Commit class but different Kind enum values).
    // Returns null for message types the spec doesn't model as Deliver actions.
    static String toTlaMessageType(String messageClass, String fieldsJson) {
        if (messageClass == null) return null;
        switch (messageClass) {
            case "PreAccept":              return "TypePreAccept";
            case "PreAcceptOk":            return "TypePreAcceptOK";
            case "Accept":                 return "TypeAccept";
            case "AcceptReply":            return "TypeAcceptOK";
            case "Commit":
                // Stable kinds: StableFastPath, StableMediumPath, StableSlowPath, StableWithTxnAndDeps.
                // Committed kinds: CommitSlowPath, CommitWithTxn.
                if (fieldsJson != null && fieldsJson.contains("\"phaseq\":\"Stable"))
                    return "TypeStable";
                return "TypeCommit";
            case "StableThenRead":         return "TypeStable";
            case "BeginRecovery":          return "TypeRecover";
            case "RecoverOk":              return "TypeRecoverOK";
            case "ReadTxnData":            return "TypeRead";
            case "Apply":                  return "TypeApply";
            case "ReadOk":
            case "ReadOkWithFutureEpoch":  return "TypeReadOk";
            default:                       return null;
        }
    }

    // Produces one JSONL line: [{"name":"Submit","params":{"p":<coordinator>,"id":<tlaId>}}]
    static String toTlaSubmitLine(int coordinator, int tlaId) {
        return "[{\"name\":\"Submit\",\"params\":{\"p\":" + coordinator + ",\"id\":" + tlaId + "}}]";
    }

    // Produces one JSONL line: [{"name":"Deliver","params":{"from":<f>,"to":<t>,"type":"<type>","id":<tlaId>}}]
    // If fieldsJson contains a "phaseq" key it is included in the output so the mapper can
    // distinguish fast-path (StableFastPath) from slow-path (StableSlowPath) TypeStable events.
    static String toTlaDeliverLine(int from, int to, String tlaType, int tlaId, @Nullable String fieldsJson) {
        StringBuilder sb = new StringBuilder(128);
        sb.append("[{\"name\":\"Deliver\",\"params\":{\"from\":").append(from)
          .append(",\"to\":").append(to)
          .append(",\"type\":\"").append(tlaType).append("\"")
          .append(",\"id\":").append(tlaId);
        String phaseq = extractField(fieldsJson, "phaseq");
        if (phaseq != null)
            sb.append(",\"phaseq\":\"").append(escape(phaseq)).append("\"");
        sb.append("}}]");
        return sb.toString();
    }

    // Extracts the string value of a named key from a simple flat JSON object, or null if absent.
    static @Nullable String extractField(@Nullable String fieldsJson, String key) {
        if (fieldsJson == null) return null;
        String needle = "\"" + key + "\":\"";
        int idx = fieldsJson.indexOf(needle);
        if (idx < 0) return null;
        int start = idx + needle.length();
        int end = start;
        while (end < fieldsJson.length()) {
            char c = fieldsJson.charAt(end);
            if (c == '\\') { end += 2; continue; }
            if (c == '"') break;
            end++;
        }
        return end <= fieldsJson.length() ? fieldsJson.substring(start, end) : null;
    }

    static String toJson(@Nullable Message message) {
        if (message == null)
            return "{}";

        StringBuilder sb = new StringBuilder(256);
        sb.append('{');

        appendString(sb, "type", String.valueOf(message.type()));
        appendString(sb, "class", message.getClass().getSimpleName());

        TxnId txnId = TxnIdExtractor.extract(message);
        if (txnId != null)
            appendString(sb, "id", String.valueOf(txnId));

        if (message instanceof PreAccept m) {
            appendString(sb, "c", String.valueOf(m.partialTxn));
            if (m.partialDeps != null) appendString(sb, "D", String.valueOf(m.partialDeps));
            appendString(sb, "acceptEpoch", String.valueOf(m.acceptEpoch));
        } else if (message instanceof PreAccept.PreAcceptOk ok) {
            appendString(sb, "id", String.valueOf(ok.txnId));
            appendString(sb, "tq", String.valueOf(ok.witnessedAt));
            appendString(sb, "Dq", String.valueOf(ok.deps));
            appendBoolean(sb, "ok", true);
        } else if (message instanceof PreAccept.PreAcceptNack) {
            appendBoolean(sb, "ok", false);
        } else if (message instanceof Accept m) {
            appendString(sb, "b", String.valueOf(m.ballot));
            appendString(sb, "t", String.valueOf(m.executeAt));
            if (m.partialDeps() != null) appendString(sb, "D", String.valueOf(m.partialDeps()));
            appendString(sb, "kind", String.valueOf(m.kind));
        } else if (message instanceof Accept.AcceptReply r) {
            appendString(sb, "outcome", String.valueOf(r.outcome));
            if (r.supersededBy != null)
                appendString(sb, "b", String.valueOf(r.supersededBy));
            if (r.deps != null)
                appendString(sb, "Dq", String.valueOf(r.deps));
            if (r.committedExecuteAt != null)
                appendString(sb, "tq", String.valueOf(r.committedExecuteAt));
        } else if (message instanceof StableThenRead m) {
            appendString(sb, "phaseq", String.valueOf(m.kind));
        } else if (message instanceof Commit m) {
            appendString(sb, "b", String.valueOf(m.ballot));
            appendString(sb, "t", String.valueOf(m.executeAt));
            if (m.partialDeps() != null)
                appendString(sb, "D", String.valueOf(m.partialDeps()));
            if (m.partialTxn() != null)
                appendString(sb, "c", String.valueOf(m.partialTxn()));
            appendString(sb, "phaseq", String.valueOf(m.kind));
        } else if (message instanceof Apply m) {
            appendString(sb, "kind", m.kind.name());
        }

        sb.append('}');
        return sb.toString();
    }

    private static void appendString(StringBuilder sb, String key, String value) {
        appendSeparator(sb);
        sb.append('"').append(escape(key)).append('"').append(':');
        sb.append('"').append(escape(value)).append('"');
    }

    private static void appendBoolean(StringBuilder sb, String key, boolean value) {
        appendSeparator(sb);
        sb.append('"').append(escape(key)).append('"').append(':').append(value);
    }

    private static void appendSeparator(StringBuilder sb) {
        if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '{')
            sb.append(',');
    }

    private static void appendParamsFromFieldsJson(StringBuilder out, @Nullable String json) {
        if (json == null)
            return;

        String s = json.trim();
        if (s.length() < 2 || s.charAt(0) != '{' || s.charAt(s.length() - 1) != '}')
            return;

        int i = 1;
        int end = s.length() - 1;
        while (i < end) {
            while (i < end && Character.isWhitespace(s.charAt(i))) i++;
            if (i < end && s.charAt(i) == ',') {
                i++;
                continue;
            }
            if (i >= end || s.charAt(i) != '"')
                break;

            int keyStart = ++i;
            while (i < end) {
                char ch = s.charAt(i);
                if (ch == '\\') i += 2;
                else if (ch == '"') break;
                else i++;
            }
            if (i >= end)
                break;

            String key = s.substring(keyStart, i);
            i++;

            while (i < end && Character.isWhitespace(s.charAt(i))) i++;
            if (i >= end || s.charAt(i) != ':')
                break;
            i++;

            while (i < end && Character.isWhitespace(s.charAt(i))) i++;
            if (i >= end)
                break;

            int valueStart = i;
            char c = s.charAt(i);
            if (c == '"') {
                i++;
                while (i < end) {
                    char ch = s.charAt(i);
                    if (ch == '\\') i += 2;
                    else if (ch == '"') {
                        i++;
                        break;
                    } else i++;
                }
            } else {
                while (i < end && s.charAt(i) != ',') i++;
                while (i > valueStart && Character.isWhitespace(s.charAt(i - 1))) i--;
            }

            if (!"type".equals(key) && !"class".equals(key)) {
                out.append(',');
                out.append('"').append(escape(key)).append('"').append(':');
                out.append(s, valueStart, i);
            }

            while (i < end && Character.isWhitespace(s.charAt(i))) i++;
            if (i < end && s.charAt(i) == ',') i++;
        }
    }

    private static String escape(String in) {
        StringBuilder sb = new StringBuilder(in.length() + 8);
        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: sb.append(c); break;
            }
        }
        return sb.toString();
    }
}
