package com.lauriewired;

import java.util.*;

/**
 * Immutable JSON value: null, boolean, number (long or double), string, array, or object.
 * <p>
 * Use the static factories and fluent builders to construct values, {@link #toJson()} to encode,
 * and {@link #parse(String)} to decode.
 */
public final class JsonValue {

    public enum Type { NULL, BOOL, LONG, DOUBLE, STRING, ARRAY, OBJECT }

    /** Singleton for the JSON {@code null} literal. */
    public static final JsonValue NULL = new JsonValue(Type.NULL, null);

    private final Type   type;
    private final Object value; // null | Boolean | Long | Double | String | List<JsonValue> | LinkedHashMap<String,JsonValue>

    private JsonValue(Type type, Object value) {
        this.type  = type;
        this.value = value;
    }

    // -------------------------------------------------------------------------
    // Factories
    // -------------------------------------------------------------------------

    public static JsonValue of(boolean b) { return new JsonValue(Type.BOOL,   b); }
    public static JsonValue of(long n)    { return new JsonValue(Type.LONG,   n); }
    public static JsonValue of(int n)     { return new JsonValue(Type.LONG,   (long) n); }
    public static JsonValue of(double n)  { return new JsonValue(Type.DOUBLE, n); }

    /** Returns {@link #NULL} when {@code s} is {@code null}. */
    public static JsonValue of(String s)  { return s == null ? NULL : new JsonValue(Type.STRING, s); }

    public static JsonValue array(List<JsonValue> items) {
        return new JsonValue(Type.ARRAY, new ArrayList<>(items));
    }

    public static JsonValue array(JsonValue... items) {
        return new JsonValue(Type.ARRAY, new ArrayList<>(Arrays.asList(items)));
    }

    public static JsonValue object(Map<String, JsonValue> entries) {
        return new JsonValue(Type.OBJECT, new LinkedHashMap<>(entries));
    }

    // -------------------------------------------------------------------------
    // Builders
    // -------------------------------------------------------------------------

    public static ObjectBuilder objectBuilder() { return new ObjectBuilder(); }
    public static ArrayBuilder  arrayBuilder()  { return new ArrayBuilder();  }

    public static final class ObjectBuilder {
        private final LinkedHashMap<String, JsonValue> map = new LinkedHashMap<>();

        public ObjectBuilder put(String key, JsonValue v) { map.put(key, v);              return this; }
        public ObjectBuilder put(String key, String  v)   { map.put(key, JsonValue.of(v)); return this; }
        public ObjectBuilder put(String key, long    v)   { map.put(key, JsonValue.of(v)); return this; }
        public ObjectBuilder put(String key, int     v)   { map.put(key, JsonValue.of(v)); return this; }
        public ObjectBuilder put(String key, boolean v)   { map.put(key, JsonValue.of(v)); return this; }

        public JsonValue build() { return JsonValue.object(map); }
    }

    public static final class ArrayBuilder {
        private final List<JsonValue> list = new ArrayList<>();

        public ArrayBuilder add(JsonValue v)  { list.add(v);              return this; }
        public ArrayBuilder add(String  v)    { list.add(JsonValue.of(v)); return this; }
        public ArrayBuilder add(long    v)    { list.add(JsonValue.of(v)); return this; }
        public ArrayBuilder add(int     v)    { list.add(JsonValue.of(v)); return this; }
        public ArrayBuilder add(boolean v)    { list.add(JsonValue.of(v)); return this; }

        public JsonValue build() { return JsonValue.array(list); }
    }

    // -------------------------------------------------------------------------
    // Type inspection
    // -------------------------------------------------------------------------

    public Type    getType()  { return type; }
    public boolean isNull()   { return type == Type.NULL;   }
    public boolean isBool()   { return type == Type.BOOL;   }
    public boolean isLong()   { return type == Type.LONG;   }
    public boolean isDouble() { return type == Type.DOUBLE; }
    public boolean isNumber() { return type == Type.LONG || type == Type.DOUBLE; }
    public boolean isString() { return type == Type.STRING; }
    public boolean isArray()  { return type == Type.ARRAY;  }
    public boolean isObject() { return type == Type.OBJECT; }

    // -------------------------------------------------------------------------
    // Accessors — throw IllegalStateException on type mismatch
    // -------------------------------------------------------------------------

    public boolean asBoolean() {
        require(Type.BOOL);
        return (Boolean) value;
    }

    /** Returns the value as a {@code long}. Coerces DOUBLE by truncation. */
    public long asLong() {
        if (type == Type.LONG)   return (Long) value;
        if (type == Type.DOUBLE) return ((Double) value).longValue();
        throw badType("number");
    }

    /** Convenience alias for {@code (int) asLong()}. */
    public int asInt() { return (int) asLong(); }

    /** Returns the value as a {@code double}. Coerces LONG exactly. */
    public double asDouble() {
        if (type == Type.DOUBLE) return (Double) value;
        if (type == Type.LONG)   return ((Long) value).doubleValue();
        throw badType("number");
    }

    public String asString() {
        require(Type.STRING);
        return (String) value;
    }

    @SuppressWarnings("unchecked")
    public List<JsonValue> asList() {
        require(Type.ARRAY);
        return Collections.unmodifiableList((List<JsonValue>) value);
    }

    @SuppressWarnings("unchecked")
    public Map<String, JsonValue> asMap() {
        require(Type.OBJECT);
        return Collections.unmodifiableMap((Map<String, JsonValue>) value);
    }

    /** Returns {@code true} iff this is an object that contains {@code key}. */
    public boolean has(String key) {
        return type == Type.OBJECT && ((Map<?,?>) value).containsKey(key);
    }

    /**
     * Returns the value for {@code key} if this is an object, or {@link #NULL} if the key is
     * absent. Throws {@link IllegalStateException} if this is not an object.
     */
    @SuppressWarnings("unchecked")
    public JsonValue get(String key) {
        require(Type.OBJECT);
        JsonValue v = ((Map<String, JsonValue>) value).get(key);
        return v != null ? v : NULL;
    }

    /**
     * Returns the element at {@code index} in this array.
     * Throws {@link IllegalStateException} if this is not an array, or
     * {@link IndexOutOfBoundsException} if the index is out of range.
     */
    @SuppressWarnings("unchecked")
    public JsonValue get(int index) {
        require(Type.ARRAY);
        List<JsonValue> list = (List<JsonValue>) value;
        if (index < 0 || index >= list.size())
            throw new IndexOutOfBoundsException("Index " + index + " out of bounds for size " + list.size());
        return list.get(index);
    }

    // -------------------------------------------------------------------------
    // Encoding
    // -------------------------------------------------------------------------

    /** Returns a compact JSON representation of this value. */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        encode(sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private void encode(StringBuilder sb) {
        switch (type) {
            case NULL:   sb.append("null"); break;
            case BOOL:   sb.append((Boolean) value ? "true" : "false"); break;
            case LONG:   sb.append(value); break;
            case DOUBLE: {
                double d = (Double) value;
                if (Double.isNaN(d) || Double.isInfinite(d)) sb.append("null");
                else sb.append(d);
                break;
            }
            case STRING:
                encodeString(sb, (String) value);
                break;
            case ARRAY: {
                sb.append('[');
                List<JsonValue> list = (List<JsonValue>) value;
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) sb.append(',');
                    list.get(i).encode(sb);
                }
                sb.append(']');
                break;
            }
            case OBJECT: {
                sb.append('{');
                boolean first = true;
                for (Map.Entry<String, JsonValue> e : ((Map<String, JsonValue>) value).entrySet()) {
                    if (!first) sb.append(',');
                    first = false;
                    encodeString(sb, e.getKey());
                    sb.append(':');
                    e.getValue().encode(sb);
                }
                sb.append('}');
                break;
            }
        }
    }

    private static void encodeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else if (Character.isHighSurrogate(c)) {
                        if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                            sb.append(String.format("\\u%04x\\u%04x", (int) c, (int) s.charAt(i + 1)));
                            i++;
                        } else {
                            sb.append(String.format("\\u%04x", (int) c)); // lone high surrogate
                        }
                    } else if (Character.isLowSurrogate(c)) {
                        sb.append(String.format("\\u%04x", (int) c)); // lone low surrogate
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    // -------------------------------------------------------------------------
    // Decoding
    // -------------------------------------------------------------------------

    /**
     * Parses a JSON string and returns the corresponding {@link JsonValue}.
     *
     * @throws IllegalArgumentException on malformed input or trailing content
     */
    public static JsonValue parse(String json) {
        if (json == null) throw new IllegalArgumentException("Input is null");
        String trimmed = json.trim();
        if (trimmed.isEmpty()) throw new IllegalArgumentException("Input is empty");
        Parser p = new Parser(trimmed);
        JsonValue result = p.parseValue();
        p.skipWhitespace();
        if (p.pos < trimmed.length())
            throw new IllegalArgumentException("Trailing content at position " + p.pos);
        return result;
    }

    private static final class Parser {
        private final String src;
        private int pos;

        Parser(String src) { this.src = src; }

        JsonValue parseValue() {
            skipWhitespace();
            if (pos >= src.length())
                throw new IllegalArgumentException("Unexpected end of input");
            char c = src.charAt(pos);
            switch (c) {
                case '{': return parseObject();
                case '[': return parseArray();
                case '"': return JsonValue.of(parseString());
                case 't': expect("true");  return JsonValue.of(true);
                case 'f': expect("false"); return JsonValue.of(false);
                case 'n': expect("null");  return JsonValue.NULL;
                default:
                    if (c == '-' || Character.isDigit(c)) return parseNumber();
                    throw new IllegalArgumentException("Unexpected character '" + c + "' at position " + pos);
            }
        }

        private JsonValue parseObject() {
            LinkedHashMap<String, JsonValue> map = new LinkedHashMap<>();
            pos++; // '{'
            skipWhitespace();
            if (peek() == '}') { pos++; return JsonValue.object(map); }
            while (pos < src.length()) {
                skipWhitespace();
                if (peek() != '"') throw new IllegalArgumentException("Expected string key at " + pos);
                String key = parseString();
                skipWhitespace();
                if (peek() != ':') throw new IllegalArgumentException("Expected ':' at " + pos);
                pos++;
                map.put(key, parseValue());
                skipWhitespace();
                char sep = peek();
                if (sep == ',') { pos++; continue; }
                if (sep == '}') { pos++; break; }
                throw new IllegalArgumentException("Expected ',' or '}' at " + pos);
            }
            return JsonValue.object(map);
        }

        private JsonValue parseArray() {
            List<JsonValue> list = new ArrayList<>();
            pos++; // '['
            skipWhitespace();
            if (peek() == ']') { pos++; return JsonValue.array(list); }
            while (pos < src.length()) {
                list.add(parseValue());
                skipWhitespace();
                char sep = peek();
                if (sep == ',') { pos++; continue; }
                if (sep == ']') { pos++; break; }
                throw new IllegalArgumentException("Expected ',' or ']' at " + pos);
            }
            return JsonValue.array(list);
        }

        private String parseString() {
            pos++; // opening '"'
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c != '\\') { sb.append(c); continue; }
                if (pos >= src.length())
                    throw new IllegalArgumentException("Truncated escape sequence");
                char esc = src.charAt(pos++);
                switch (esc) {
                    case '"':  sb.append('"');  break;
                    case '\\': sb.append('\\'); break;
                    case '/':  sb.append('/');  break;
                    case 'n':  sb.append('\n'); break;
                    case 'r':  sb.append('\r'); break;
                    case 't':  sb.append('\t'); break;
                    case 'b':  sb.append('\b'); break;
                    case 'f':  sb.append('\f'); break;
                    case 'u':
                        if (pos + 4 > src.length())
                            throw new IllegalArgumentException("Truncated \\u escape at " + pos);
                        sb.append((char) Integer.parseInt(src.substring(pos, pos + 4), 16));
                        pos += 4;
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown escape '\\" + esc + "'");
                }
            }
            throw new IllegalArgumentException("Unterminated string");
        }

        private JsonValue parseNumber() {
            int start = pos;
            if (src.charAt(pos) == '-') pos++;
            while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            boolean isFloat = false;
            if (pos < src.length() && src.charAt(pos) == '.') {
                isFloat = true; pos++;
                while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            }
            if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
                isFloat = true; pos++;
                if (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
                while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            }
            String num = src.substring(start, pos);
            try {
                return isFloat ? JsonValue.of(Double.parseDouble(num))
                               : JsonValue.of(Long.parseLong(num));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid number: " + num);
            }
        }

        private void expect(String literal) {
            if (!src.startsWith(literal, pos))
                throw new IllegalArgumentException("Expected '" + literal + "' at " + pos);
            pos += literal.length();
        }

        private char peek() { return pos < src.length() ? src.charAt(pos) : '\0'; }

        void skipWhitespace() {
            while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) pos++;
        }
    }

    // -------------------------------------------------------------------------
    // Object identity
    // -------------------------------------------------------------------------

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JsonValue)) return false;
        JsonValue other = (JsonValue) o;
        return type == other.type && Objects.equals(value, other.value);
    }

    @Override public int hashCode() { return Objects.hash(type, value); }

    /** Same as {@link #toJson()}. */
    @Override public String toString() { return toJson(); }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private void require(Type expected) {
        if (type != expected) throw badType(expected.name().toLowerCase());
    }

    private IllegalStateException badType(String expected) {
        return new IllegalStateException("Expected " + expected + " but got " + type);
    }
}
