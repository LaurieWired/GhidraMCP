package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static com.lauriewired.util.ParseUtils.parseIntOrDefault;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class GetAllFunctionNames extends Handler {
    public GetAllFunctionNames(PluginTool tool) {
        super(tool, "/methods");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Map<String, String> qparams = parseQueryParams(exchange);
        int offset = parseIntOrDefault(qparams.get("offset"), 0);
        int limit  = parseIntOrDefault(qparams.get("limit"),  100);
        sendResponse(exchange, generateResponse(offset, limit));
    }

    private String generateResponse(int offset, int limit) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }
}
