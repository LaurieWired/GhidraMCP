package com.lauriewired.ghidramcp.http;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import com.lauriewired.ghidramcp.core.McpException;
import com.sun.net.httpserver.HttpExchange;

/**
 * Parameters of a backend request, merged from the query string and a form-encoded body.
 */
public final class Request {

	private final Map<String, String> params;

	private Request(Map<String, String> params) {
		this.params = params;
	}

	static Request parse(HttpExchange exchange) throws IOException {
		Map<String, String> params = new HashMap<>();
		decodeInto(exchange.getRequestURI().getRawQuery(), params);
		byte[] body = exchange.getRequestBody().readAllBytes();
		if (body.length > 0) {
			decodeInto(new String(body, StandardCharsets.UTF_8), params);
		}
		return new Request(params);
	}

	private static void decodeInto(String encoded, Map<String, String> params) {
		if (encoded == null || encoded.isEmpty()) {
			return;
		}
		for (String pair : encoded.split("&")) {
			if (pair.isEmpty()) {
				continue;
			}
			int eq = pair.indexOf('=');
			String key = eq < 0 ? pair : pair.substring(0, eq);
			String value = eq < 0 ? "" : pair.substring(eq + 1);
			params.put(URLDecoder.decode(key, StandardCharsets.UTF_8),
				URLDecoder.decode(value, StandardCharsets.UTF_8));
		}
	}

	public String optional(String name) {
		return params.get(name);
	}

	public String required(String name) {
		String value = params.get(name);
		if (value == null || value.isEmpty()) {
			throw McpException.missingParameter(name);
		}
		return value;
	}

	/** A parameter that must be present but may be empty. */
	public String present(String name) {
		String value = params.get(name);
		if (value == null) {
			throw McpException.missingParameter(name);
		}
		return value;
	}

	public int intParam(String name, int defaultValue) {
		String value = params.get(name);
		if (value == null || value.isEmpty()) {
			return defaultValue;
		}
		try {
			return Integer.parseInt(value.trim());
		}
		catch (NumberFormatException e) {
			throw McpException.invalidParameter(name + " must be an integer (got '" + value + "')");
		}
	}

	public int offset() {
		return Math.max(0, intParam("offset", 0));
	}

	public int limit(int defaultValue) {
		return intParam("limit", defaultValue);
	}
}
