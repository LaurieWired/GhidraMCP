package com.lauriewired.handlers.get;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.lauriewired.util.ParseUtils.*;
import static ghidra.program.util.GhidraProgramUtilities.getCurrentProgram;

public final class ListSegments extends Handler {
    public ListSegments(PluginTool tool) {
        super(tool, "/segments");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Map<String, String> qparams = parseQueryParams(exchange);
        int offset = parseIntOrDefault(qparams.get("offset"), 0);
        int limit  = parseIntOrDefault(qparams.get("limit"),  100);
        sendResponse(exchange, listSegments(offset, limit));
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram(tool);
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }
}
