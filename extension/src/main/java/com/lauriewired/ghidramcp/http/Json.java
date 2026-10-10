package com.lauriewired.ghidramcp.http;

import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * The backend response envelope: {"success": true, "data": ...} or
 * {"success": false, "error": {"code": ..., "message": ...}}.
 */
public final class Json {

	private static final Gson GSON = new GsonBuilder()
			.setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
			.serializeNulls()
			.disableHtmlEscaping()
			.create();

	private Json() {
	}

	public static String success(Object data) {
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("success", true);
		body.put("data", data);
		return GSON.toJson(body);
	}

	public static String error(String code, String message) {
		Map<String, Object> error = new LinkedHashMap<>();
		error.put("code", code);
		error.put("message", message);
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("success", false);
		body.put("error", error);
		return GSON.toJson(body);
	}
}
