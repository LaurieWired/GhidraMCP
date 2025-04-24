package com.lauriewired.handlers.comment;

import com.lauriewired.handlers.Handler;
import com.sun.net.httpserver.HttpExchange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CodeUnit;

import java.util.Map;

import static com.lauriewired.util.GhidraUtils.setCommentAtAddress;
import static com.lauriewired.util.ParseUtils.parsePostParams;
import static com.lauriewired.util.ParseUtils.sendResponse;

public final class SetDecompilerComment extends Handler {
    public SetDecompilerComment(PluginTool tool) {
        super(tool, "/set_decompiler_comment");
    }

    @Override
    public void handle(HttpExchange exchange) throws Exception {
        Map<String, String> params = parsePostParams(exchange);
        String address = params.get("address");
        String comment = params.get("comment");
        boolean success = setDecompilerComment(address, comment);
        sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(tool, addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }
}
