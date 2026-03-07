package com.lauriewired;

import junit.framework.TestCase;
import java.util.List;
import java.util.Map;

public class JsonValueTest extends TestCase {

    // =========================================================================
    // parse — scalars
    // =========================================================================

    public void testParseNull() {
        JsonValue v = JsonValue.parse("null");
        assertTrue(v.isNull());
        assertEquals(JsonValue.Type.NULL, v.getType());
    }

    public void testParseTrue() {
        JsonValue v = JsonValue.parse("true");
        assertTrue(v.isBool());
        assertTrue(v.asBoolean());
    }

    public void testParseFalse() {
        JsonValue v = JsonValue.parse("false");
        assertTrue(v.isBool());
        assertFalse(v.asBoolean());
    }

    public void testParseZero() {
        JsonValue v = JsonValue.parse("0");
        assertTrue(v.isLong());
        assertEquals(0L, v.asLong());
    }

    public void testParsePositiveInteger() {
        JsonValue v = JsonValue.parse("42");
        assertTrue(v.isLong());
        assertEquals(42L, v.asLong());
        assertEquals(42, v.asInt());
    }

    public void testParseNegativeInteger() {
        JsonValue v = JsonValue.parse("-7");
        assertEquals(-7L, v.asLong());
    }

    public void testParseLargeInteger() {
        long big = Long.MAX_VALUE;
        JsonValue v = JsonValue.parse(String.valueOf(big));
        assertEquals(big, v.asLong());
    }

    public void testParseDouble() {
        JsonValue v = JsonValue.parse("3.14");
        assertTrue(v.isDouble());
        assertEquals(3.14, v.asDouble(), 1e-9);
    }

    public void testParseNegativeDouble() {
        JsonValue v = JsonValue.parse("-2.5");
        assertEquals(-2.5, v.asDouble(), 1e-9);
    }

    public void testParseExponentDouble() {
        JsonValue v = JsonValue.parse("1e3");
        assertTrue(v.isDouble());
        assertEquals(1000.0, v.asDouble(), 1e-9);
    }

    public void testParseNegativeExponent() {
        JsonValue v = JsonValue.parse("2.5e-2");
        assertEquals(0.025, v.asDouble(), 1e-9);
    }

    public void testParseSimpleString() {
        JsonValue v = JsonValue.parse("\"hello\"");
        assertTrue(v.isString());
        assertEquals("hello", v.asString());
    }

    public void testParseEmptyString() {
        assertEquals("", JsonValue.parse("\"\"").asString());
    }

    public void testParseStringWithEscapeQuote() {
        assertEquals("a\"b", JsonValue.parse("\"a\\\"b\"").asString());
    }

    public void testParseStringWithEscapeBackslash() {
        assertEquals("a\\b", JsonValue.parse("\"a\\\\b\"").asString());
    }

    public void testParseStringWithEscapeNewline() {
        assertEquals("a\nb", JsonValue.parse("\"a\\nb\"").asString());
    }

    public void testParseStringWithEscapeTab() {
        assertEquals("a\tb", JsonValue.parse("\"a\\tb\"").asString());
    }

    public void testParseStringWithEscapeCarriageReturn() {
        assertEquals("a\rb", JsonValue.parse("\"a\\rb\"").asString());
    }

    public void testParseStringWithEscapeBackspace() {
        assertEquals("a\bb", JsonValue.parse("\"a\\bb\"").asString());
    }

    public void testParseStringWithEscapeFormFeed() {
        assertEquals("a\fb", JsonValue.parse("\"a\\fb\"").asString());
    }

    public void testParseStringWithEscapeForwardSlash() {
        assertEquals("a/b", JsonValue.parse("\"a\\/b\"").asString());
    }

    public void testParseStringWithUnicodeEscape() {
        assertEquals("A", JsonValue.parse("\"\\u0041\"").asString());
    }

    public void testParseStringWithHighUnicode() {
        assertEquals("\u4e2d", JsonValue.parse("\"\\u4e2d\"").asString());
    }

    // =========================================================================
    // parse — objects
    // =========================================================================

    public void testParseEmptyObject() {
        JsonValue v = JsonValue.parse("{}");
        assertTrue(v.isObject());
        assertTrue(v.asMap().isEmpty());
    }

    public void testParseSimpleObject() {
        JsonValue v = JsonValue.parse("{\"key\":\"value\"}");
        assertTrue(v.isObject());
        assertEquals("value", v.get("key").asString());
    }

    public void testParseObjectMultipleKeys() {
        JsonValue v = JsonValue.parse("{\"a\":1,\"b\":2,\"c\":3}");
        assertEquals(1L, v.get("a").asLong());
        assertEquals(2L, v.get("b").asLong());
        assertEquals(3L, v.get("c").asLong());
    }

    public void testParseObjectWithNullValue() {
        JsonValue v = JsonValue.parse("{\"x\":null}");
        assertTrue(v.get("x").isNull());
    }

    public void testParseObjectWithBoolValue() {
        JsonValue v = JsonValue.parse("{\"ok\":true}");
        assertTrue(v.get("ok").asBoolean());
    }

    public void testParseNestedObject() {
        JsonValue v = JsonValue.parse("{\"outer\":{\"inner\":42}}");
        assertEquals(42L, v.get("outer").get("inner").asLong());
    }

    public void testParseObjectPreservesInsertionOrder() {
        JsonValue v = JsonValue.parse("{\"z\":1,\"a\":2,\"m\":3}");
        List<String> keys = new java.util.ArrayList<>(v.asMap().keySet());
        assertEquals("z", keys.get(0));
        assertEquals("a", keys.get(1));
        assertEquals("m", keys.get(2));
    }

    public void testParseObjectWithWhitespace() {
        JsonValue v = JsonValue.parse("{ \"k\" : \"v\" }");
        assertEquals("v", v.get("k").asString());
    }

    // =========================================================================
    // parse — arrays
    // =========================================================================

    public void testParseEmptyArray() {
        JsonValue v = JsonValue.parse("[]");
        assertTrue(v.isArray());
        assertTrue(v.asList().isEmpty());
    }

    public void testParseSimpleArray() {
        JsonValue v = JsonValue.parse("[1,2,3]");
        assertEquals(3, v.asList().size());
        assertEquals(1L, v.get(0).asLong());
        assertEquals(2L, v.get(1).asLong());
        assertEquals(3L, v.get(2).asLong());
    }

    public void testParseMixedArray() {
        JsonValue v = JsonValue.parse("[null,true,1,\"x\"]");
        assertTrue(v.get(0).isNull());
        assertTrue(v.get(1).asBoolean());
        assertEquals(1L, v.get(2).asLong());
        assertEquals("x", v.get(3).asString());
    }

    public void testParseNestedArray() {
        JsonValue v = JsonValue.parse("[[1,2],[3,4]]");
        assertEquals(1L, v.get(0).get(0).asLong());
        assertEquals(4L, v.get(1).get(1).asLong());
    }

    public void testParseArrayOfObjects() {
        JsonValue v = JsonValue.parse("[{\"n\":\"a\"},{\"n\":\"b\"}]");
        assertEquals("a", v.get(0).get("n").asString());
        assertEquals("b", v.get(1).get("n").asString());
    }

    public void testParseObjectWithArray() {
        JsonValue v = JsonValue.parse("{\"items\":[1,2,3]}");
        assertEquals(2L, v.get("items").get(1).asLong());
    }

    // =========================================================================
    // parse — whitespace and leading/trailing space
    // =========================================================================

    public void testParseWithLeadingTrailingWhitespace() {
        JsonValue v = JsonValue.parse("  42  ");
        assertEquals(42L, v.asLong());
    }

    public void testParseIndentedJson() {
        String json = "{\n  \"name\": \"test\",\n  \"value\": 99\n}";
        JsonValue v = JsonValue.parse(json);
        assertEquals("test", v.get("name").asString());
        assertEquals(99L, v.get("value").asLong());
    }

    // =========================================================================
    // parse — error cases
    // =========================================================================

    public void testParseNullInput() {
        try {
            JsonValue.parse(null);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    public void testParseEmptyInput() {
        try {
            JsonValue.parse("  ");
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    public void testParseUnterminatedString() {
        try {
            JsonValue.parse("\"hello");
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    public void testParseUnterminatedObject() {
        try {
            JsonValue.parse("{\"key\":1");
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    public void testParseUnterminatedArray() {
        try {
            JsonValue.parse("[1,2");
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    public void testParseUnknownEscape() {
        try {
            JsonValue.parse("\"\\q\"");
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    public void testParseTrailingContent() {
        try {
            JsonValue.parse("true false");
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    public void testParseUnexpectedCharacter() {
        try {
            JsonValue.parse("?");
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) { /* expected */ }
    }

    // =========================================================================
    // encode
    // =========================================================================

    public void testEncodeNull() {
        assertEquals("null", JsonValue.NULL.toJson());
    }

    public void testEncodeTrue() {
        assertEquals("true", JsonValue.of(true).toJson());
    }

    public void testEncodeFalse() {
        assertEquals("false", JsonValue.of(false).toJson());
    }

    public void testEncodeLong() {
        assertEquals("42", JsonValue.of(42L).toJson());
    }

    public void testEncodeNegativeLong() {
        assertEquals("-1", JsonValue.of(-1L).toJson());
    }

    public void testEncodeInt() {
        assertEquals("7", JsonValue.of(7).toJson());
    }

    public void testEncodeDouble() {
        assertEquals("3.14", JsonValue.of(3.14).toJson());
    }

    public void testEncodeNaNAsNull() {
        assertEquals("null", JsonValue.of(Double.NaN).toJson());
    }

    public void testEncodeInfinityAsNull() {
        assertEquals("null", JsonValue.of(Double.POSITIVE_INFINITY).toJson());
        assertEquals("null", JsonValue.of(Double.NEGATIVE_INFINITY).toJson());
    }

    public void testEncodeSimpleString() {
        assertEquals("\"hello\"", JsonValue.of("hello").toJson());
    }

    public void testEncodeStringWithQuote() {
        assertEquals("\"a\\\"b\"", JsonValue.of("a\"b").toJson());
    }

    public void testEncodeStringWithBackslash() {
        assertEquals("\"a\\\\b\"", JsonValue.of("a\\b").toJson());
    }

    public void testEncodeStringWithNewline() {
        assertEquals("\"a\\nb\"", JsonValue.of("a\nb").toJson());
    }

    public void testEncodeStringWithTab() {
        assertEquals("\"a\\tb\"", JsonValue.of("a\tb").toJson());
    }

    public void testEncodeStringWithControlChar() {
        assertEquals("\"\\u0001\"", JsonValue.of("\u0001").toJson());
    }

    public void testEncodeStringSurrogatePair() {
        // U+1F600 GRINNING FACE — encoded in Java as surrogate pair \uD83D\uDE00
        String emoji = "\uD83D\uDE00";
        assertEquals("\"\\ud83d\\ude00\"", JsonValue.of(emoji).toJson());
    }

    public void testEncodeStringLoneHighSurrogate() {
        String lone = "\uD83D"; // high surrogate with no following low surrogate
        assertEquals("\"\\ud83d\"", JsonValue.of(lone).toJson());
    }

    public void testEncodeStringLoneLowSurrogate() {
        String lone = "\uDE00"; // low surrogate with no preceding high surrogate
        assertEquals("\"\\ude00\"", JsonValue.of(lone).toJson());
    }

    public void testEncodeEmptyObject() {
        assertEquals("{}", JsonValue.objectBuilder().build().toJson());
    }

    public void testEncodeSimpleObject() {
        String json = JsonValue.objectBuilder().put("k", "v").build().toJson();
        assertEquals("{\"k\":\"v\"}", json);
    }

    public void testEncodeObjectInsertionOrder() {
        String json = JsonValue.objectBuilder()
            .put("z", 1).put("a", 2).put("m", 3).build().toJson();
        assertEquals("{\"z\":1,\"a\":2,\"m\":3}", json);
    }

    public void testEncodeEmptyArray() {
        assertEquals("[]", JsonValue.arrayBuilder().build().toJson());
    }

    public void testEncodeArray() {
        assertEquals("[1,2,3]", JsonValue.arrayBuilder().add(1).add(2).add(3).build().toJson());
    }

    public void testEncodeNestedStructure() {
        JsonValue v = JsonValue.objectBuilder()
            .put("items", JsonValue.arrayBuilder().add("x").add("y").build())
            .put("count", 2)
            .build();
        assertEquals("{\"items\":[\"x\",\"y\"],\"count\":2}", v.toJson());
    }

    public void testEncodeNullString() {
        assertEquals("null", JsonValue.of((String) null).toJson());
    }

    // =========================================================================
    // round-trip
    // =========================================================================

    public void testRoundTripObject() {
        String src = "{\"a\":1,\"b\":\"two\",\"c\":true,\"d\":null}";
        assertEquals(src, JsonValue.parse(src).toJson());
    }

    public void testRoundTripArray() {
        String src = "[1,\"two\",false,null,[3,4]]";
        assertEquals(src, JsonValue.parse(src).toJson());
    }

    public void testRoundTripNested() {
        String src = "{\"x\":{\"y\":[1,2,{\"z\":3}]}}";
        assertEquals(src, JsonValue.parse(src).toJson());
    }

    // =========================================================================
    // accessor edge cases
    // =========================================================================

    public void testGetMissingKeyReturnsNull() {
        JsonValue obj = JsonValue.parse("{\"a\":1}");
        assertTrue(obj.get("missing").isNull());
    }

    public void testHasKey() {
        JsonValue obj = JsonValue.objectBuilder().put("k", "v").build();
        assertTrue(obj.has("k"));
        assertFalse(obj.has("nope"));
    }

    public void testHasOnNonObject() {
        assertFalse(JsonValue.of(1).has("k"));
        assertFalse(JsonValue.NULL.has("k"));
    }

    public void testAsMapIsUnmodifiable() {
        JsonValue obj = JsonValue.objectBuilder().put("k", "v").build();
        Map<String, JsonValue> map = obj.asMap();
        try {
            map.put("extra", JsonValue.of(1));
            fail("Expected UnsupportedOperationException");
        } catch (UnsupportedOperationException e) { /* expected */ }
    }

    public void testAsListIsUnmodifiable() {
        JsonValue arr = JsonValue.arrayBuilder().add(1).build();
        List<JsonValue> list = arr.asList();
        try {
            list.add(JsonValue.of(2));
            fail("Expected UnsupportedOperationException");
        } catch (UnsupportedOperationException e) { /* expected */ }
    }

    public void testGetByIndexOutOfBounds() {
        JsonValue arr = JsonValue.parse("[1,2]");
        try {
            arr.get(5);
            fail("Expected IndexOutOfBoundsException");
        } catch (IndexOutOfBoundsException e) { /* expected */ }
    }

    public void testGetByNegativeIndex() {
        JsonValue arr = JsonValue.parse("[1]");
        try {
            arr.get(-1);
            fail("Expected IndexOutOfBoundsException");
        } catch (IndexOutOfBoundsException e) { /* expected */ }
    }

    public void testGetStringKeyOnNonObject() {
        try {
            JsonValue.of(1).get("k");
            fail("Expected IllegalStateException");
        } catch (IllegalStateException e) { /* expected */ }
    }

    public void testGetIndexOnNonArray() {
        try {
            JsonValue.objectBuilder().build().get(0);
            fail("Expected IllegalStateException");
        } catch (IllegalStateException e) { /* expected */ }
    }

    public void testTypeMismatchBoolean() {
        try { JsonValue.of(1L).asBoolean(); fail(); } catch (IllegalStateException e) { /* expected */ }
    }

    public void testTypeMismatchString() {
        try { JsonValue.of(true).asString(); fail(); } catch (IllegalStateException e) { /* expected */ }
    }

    public void testTypeMismatchList() {
        try { JsonValue.of("x").asList(); fail(); } catch (IllegalStateException e) { /* expected */ }
    }

    public void testTypeMismatchMap() {
        try { JsonValue.arrayBuilder().build().asMap(); fail(); } catch (IllegalStateException e) { /* expected */ }
    }

    public void testAsIntFromLong() {
        assertEquals(5, JsonValue.of(5L).asInt());
    }

    public void testAsIntFromDouble() {
        assertEquals(3, JsonValue.of(3.9).asInt());
    }

    public void testAsDoubleFromLong() {
        assertEquals(2.0, JsonValue.of(2L).asDouble(), 1e-9);
    }

    public void testAsLongFromDouble() {
        assertEquals(3L, JsonValue.of(3.7).asLong());
    }

    // =========================================================================
    // factories
    // =========================================================================

    public void testOfNullString() {
        assertSame(JsonValue.NULL, JsonValue.of((String) null));
    }

    public void testArrayVarargs() {
        JsonValue arr = JsonValue.array(JsonValue.of(1), JsonValue.of(2));
        assertEquals(2, arr.asList().size());
        assertEquals(1L, arr.get(0).asLong());
    }

    public void testObjectFactory() {
        Map<String, JsonValue> map = new java.util.LinkedHashMap<>();
        map.put("k", JsonValue.of("v"));
        JsonValue obj = JsonValue.object(map);
        assertEquals("v", obj.get("k").asString());
    }

    // =========================================================================
    // builders
    // =========================================================================

    public void testObjectBuilderAllOverloads() {
        JsonValue obj = JsonValue.objectBuilder()
            .put("s", "str")
            .put("l", 10L)
            .put("i", 20)
            .put("b", true)
            .put("v", JsonValue.NULL)
            .build();
        assertEquals("str",           obj.get("s").asString());
        assertEquals(10L,             obj.get("l").asLong());
        assertEquals(20,              obj.get("i").asInt());
        assertTrue(                   obj.get("b").asBoolean());
        assertTrue(                   obj.get("v").isNull());
    }

    public void testArrayBuilderAllOverloads() {
        JsonValue arr = JsonValue.arrayBuilder()
            .add("str")
            .add(10L)
            .add(20)
            .add(false)
            .add(JsonValue.NULL)
            .build();
        assertEquals("str", arr.get(0).asString());
        assertEquals(10L,   arr.get(1).asLong());
        assertEquals(20,    arr.get(2).asInt());
        assertFalse(        arr.get(3).asBoolean());
        assertTrue(         arr.get(4).isNull());
    }

    public void testBuilderPreservesInsertionOrder() {
        JsonValue obj = JsonValue.objectBuilder()
            .put("c", 3).put("b", 2).put("a", 1).build();
        List<String> keys = new java.util.ArrayList<>(obj.asMap().keySet());
        assertEquals("c", keys.get(0));
        assertEquals("b", keys.get(1));
        assertEquals("a", keys.get(2));
    }

    // =========================================================================
    // equals / hashCode / toString
    // =========================================================================

    public void testEqualsNull() {
        assertEquals(JsonValue.NULL, JsonValue.NULL);
        assertEquals(JsonValue.NULL, JsonValue.parse("null"));
    }

    public void testEqualsString() {
        assertEquals(JsonValue.of("a"), JsonValue.of("a"));
        assertFalse(JsonValue.of("a").equals(JsonValue.of("b")));
    }

    public void testEqualsLong() {
        assertEquals(JsonValue.of(1L), JsonValue.of(1L));
        assertFalse(JsonValue.of(1L).equals(JsonValue.of(2L)));
    }

    public void testEqualsLongAndDoubleNotEqual() {
        assertFalse(JsonValue.of(1L).equals(JsonValue.of(1.0)));
    }

    public void testEqualsObject() {
        JsonValue a = JsonValue.objectBuilder().put("k", "v").build();
        JsonValue b = JsonValue.objectBuilder().put("k", "v").build();
        assertEquals(a, b);
    }

    public void testEqualsArray() {
        JsonValue a = JsonValue.arrayBuilder().add(1).add(2).build();
        JsonValue b = JsonValue.arrayBuilder().add(1).add(2).build();
        assertEquals(a, b);
    }

    public void testHashCodeConsistentWithEquals() {
        JsonValue a = JsonValue.objectBuilder().put("x", 1).build();
        JsonValue b = JsonValue.objectBuilder().put("x", 1).build();
        assertEquals(a.hashCode(), b.hashCode());
    }

    public void testToStringIsSameAsToJson() {
        JsonValue v = JsonValue.objectBuilder().put("k", "v").build();
        assertEquals(v.toJson(), v.toString());
    }
}
