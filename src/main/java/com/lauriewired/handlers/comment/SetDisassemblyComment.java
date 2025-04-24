package com.lauriewired.handlers.comment;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CodeUnit;

import java.util.Map;

import static com.lauriewired.util.GhidraUtils.setCommentAtAddress;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;

public final class SetDisassemblyComment extends Handler {
    public SetDisassemblyComment(PluginTool tool) {
        super(tool, "/set_disassembly_comment");
    }

    @Override
    public void handle(HttpExchange exchange) throws Exception {
        Map<String, String> params = parsePostParams(exchange);
        String address = params.get("address");
        String comment = params.get("comment");
        boolean success = setDisassemblyComment(address, comment);
        sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(tool, addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }
}
