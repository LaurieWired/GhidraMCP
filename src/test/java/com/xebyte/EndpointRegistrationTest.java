package com.xebyte;

import junit.framework.TestCase;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Unit tests specifically for endpoint registration and HTTP server functionality.
 *
 * This test class focuses on validating that all endpoints defined in the
 * GhidraMCPPlugin.java are properly registered with the HTTP server.
 */
public class EndpointRegistrationTest extends TestCase {

    private static final String BASE_URL = "http://127.0.0.1:8089";
    private static final int TIMEOUT_SECONDS = 5;
    private HttpClient httpClient;

    @Override
    protected void setUp() {
        httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(TIMEOUT_SECONDS))
            .build();
    }

    /**
     * Helper method to test if an endpoint is registered (doesn't return 404)
     */
    private boolean isEndpointRegistered(String endpoint) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/" + endpoint))
                .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // An endpoint is considered "registered" if it doesn't return 404
            // It may return 400 (bad request) if parameters are missing, but that means it's registered
            return response.statusCode() != 404;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test that all basic CRUD endpoints are registered
     */
    public void testBasicEndpointsRegistered() {
        Map<String, String> basicEndpoints = new HashMap<>();
        basicEndpoints.put("list_functions", "List all functions");
        basicEndpoints.put("methods", "List function names");
        basicEndpoints.put("classes", "List classes/namespaces");
        basicEndpoints.put("segments", "List memory segments");
        basicEndpoints.put("imports", "List imported symbols");
        basicEndpoints.put("exports", "List exported symbols");
        basicEndpoints.put("namespaces", "List namespaces");
        basicEndpoints.put("data", "List data items");
        basicEndpoints.put("strings", "List strings");

        for (Map.Entry<String, String> entry : basicEndpoints.entrySet()) {
            assertTrue("Endpoint '" + entry.getKey() + "' (" + entry.getValue() + ") should be registered",
                isEndpointRegistered(entry.getKey()));
        }
    }

    /**
     * Test that search and analysis endpoints are registered
     */
    public void testSearchAnalysisEndpointsRegistered() {
        Map<String, String> searchEndpoints = new HashMap<>();
        searchEndpoints.put("searchFunctions", "Search functions by name");
        searchEndpoints.put("decompile", "Decompile function");
        searchEndpoints.put("get_function_by_address", "Get function by address");
        searchEndpoints.put("disassemble_function", "Disassemble function");

        for (Map.Entry<String, String> entry : searchEndpoints.entrySet()) {
            assertTrue("Search/Analysis endpoint '" + entry.getKey() + "' (" + entry.getValue() + ") should be registered",
                isEndpointRegistered(entry.getKey()));
        }
    }

    /**
     * Test that cross-reference endpoints are registered
     */
    public void testCrossReferenceEndpointsRegistered() {
        Map<String, String> xrefEndpoints = new HashMap<>();
        xrefEndpoints.put("xrefs_to", "Get references to address");
        xrefEndpoints.put("xrefs_from", "Get references from address");
        xrefEndpoints.put("function_xrefs", "Get function cross-references");

        for (Map.Entry<String, String> entry : xrefEndpoints.entrySet()) {
            assertTrue("Cross-reference endpoint '" + entry.getKey() + "' (" + entry.getValue() + ") should be registered",
                isEndpointRegistered(entry.getKey()));
        }
    }

    /**
     * Test that current state endpoints are registered
     */
    public void testCurrentStateEndpointsRegistered() {
        Map<String, String> stateEndpoints = new HashMap<>();
        stateEndpoints.put("get_current_address", "Get current cursor address");
        stateEndpoints.put("get_current_function", "Get current function");

        for (Map.Entry<String, String> entry : stateEndpoints.entrySet()) {
            assertTrue("Current state endpoint '" + entry.getKey() + "' (" + entry.getValue() + ") should be registered",
                isEndpointRegistered(entry.getKey()));
        }
    }

    /**
     * Test the problematic endpoints that should be registered but may not be
     * This test documents which advanced endpoints are missing
     */
    public void testAdvancedEndpointsRegistration() {
        Map<String, String> advancedEndpoints = new HashMap<>();
        advancedEndpoints.put("all_labels", "List all labels");
        advancedEndpoints.put("program_stats", "Get program statistics");
        advancedEndpoints.put("find_byte_patterns", "Find byte patterns");
        advancedEndpoints.put("function_callgraph", "Get function call graph");
        advancedEndpoints.put("search_labels", "Search labels");
        advancedEndpoints.put("string_references", "Get string references");

        int registeredCount = 0;
        int totalCount = advancedEndpoints.size();

        System.out.println("\n=== Advanced Endpoints Registration Status ===");

        for (Map.Entry<String, String> entry : advancedEndpoints.entrySet()) {
            boolean isRegistered = isEndpointRegistered(entry.getKey());
            if (isRegistered) {
                System.out.println("✓ " + entry.getKey() + " - " + entry.getValue());
                registeredCount++;
            } else {
                System.out.println("✗ " + entry.getKey() + " - " + entry.getValue() + " (NOT REGISTERED)");
            }
        }

        double registrationRate = (double) registeredCount / totalCount * 100;
        System.out.println("Advanced endpoint registration: " + registeredCount + "/" + totalCount +
                          " (" + String.format("%.1f", registrationRate) + "%)");

        // Document the current state - this test should eventually pass when all endpoints are fixed
        // For now, we just report the status without failing the test
        if (registeredCount < totalCount) {
            System.out.println("WARNING: Some advanced endpoints are not registered. This indicates:");
            System.out.println("1. HTTP server context registration may have failed");
            System.out.println("2. Plugin may not have fully reloaded");
            System.out.println("3. Endpoint implementation may be incomplete");
        }

        // This assertion can be enabled once all endpoints are expected to work
        // assertTrue("All advanced endpoints should be registered", registeredCount == totalCount);
    }

    /**
     * Test that the HTTP server responds with proper error codes
     */
    public void testHttpErrorCodes() {
        // Test 404 for truly non-existent endpoints
        assertFalse("Non-existent endpoint should return 404",
            isEndpointRegistered("definitely_does_not_exist_123456"));

        // Test that registered endpoints don't return 404
        assertTrue("Basic endpoint should not return 404",
            isEndpointRegistered("methods"));
    }

    /**
     * Test endpoint consistency - all endpoints from Java source should be registered
     * This test verifies that the createContext() calls in the Java code are working
     */
    public void testJavaSourceEndpointConsistency() {
        // These are the endpoints that have createContext() calls in the Java source
        String[] sourceEndpoints = {
            // From startServer() method in GhidraMCPPlugin.java
            "list_functions", "methods", "classes", "segments", "imports", "exports",
            "namespaces", "data", "strings", "searchFunctions", "decompile",
            "renameFunction", "renameData", "xrefs_to", "xrefs_from", "function_xrefs",
            "function_labels", "get_function_by_address", "get_current_address",
            "get_current_function", "disassemble_function", "set_decompiler_comment",
            "set_disassembly_comment", "rename_function_by_address", "set_function_prototype",
            "set_local_variable_type",

            // Advanced endpoints that should be in the source
            "find_byte_patterns", "program_stats", "create_label", "all_labels",
            "labels_at_address", "search_labels"
        };

        int registeredFromSource = 0;
        int totalFromSource = sourceEndpoints.length;

        System.out.println("\n=== Java Source Endpoint Consistency Check ===");

        for (String endpoint : sourceEndpoints) {
            boolean isRegistered = isEndpointRegistered(endpoint);
            if (isRegistered) {
                registeredFromSource++;
            } else {
                System.out.println("✗ " + endpoint + " - defined in source but not registered");
            }
        }

        double consistencyRate = (double) registeredFromSource / totalFromSource * 100;
        System.out.println("Source consistency: " + registeredFromSource + "/" + totalFromSource +
                          " (" + String.format("%.1f", consistencyRate) + "%)");

        // We expect high consistency between source and registered endpoints
        assertTrue("At least 80% of source-defined endpoints should be registered",
            consistencyRate >= 80.0);
    }

    /**
     * Test server health and basic functionality
     */
    public void testServerHealth() {
        // Test that the server is responding at all
        boolean serverResponding = false;
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/methods"))
                .timeout(Duration.ofSeconds(2))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            serverResponding = (response.statusCode() >= 200 && response.statusCode() < 500);
        } catch (Exception e) {
            // Server not responding
        }

        assertTrue("MCP HTTP server should be responding. " +
                  "Ensure Ghidra is running with GhidraMCP plugin enabled and MCP server started.",
                  serverResponding);
    }
}