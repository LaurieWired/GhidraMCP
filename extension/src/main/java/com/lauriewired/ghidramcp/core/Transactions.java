package com.lauriewired.ghidramcp.core;

import com.lauriewired.ghidramcp.core.GhidraAnalysisService.WriteExecutor;

import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Runs program modifications inside a transaction on the write thread, rolling back on failure and
 * mapping Ghidra exceptions to {@link McpException}s.
 */
final class Transactions {

	@FunctionalInterface
	interface WriteAction<T> {
		T run() throws Exception;
	}

	private final WriteExecutor writeExecutor;

	Transactions(WriteExecutor writeExecutor) {
		this.writeExecutor = writeExecutor;
	}

	<T> T write(Program program, String transactionName, WriteAction<T> action) {
		return writeExecutor.execute(() -> {
			int tx = program.startTransaction(transactionName);
			boolean commit = false;
			try {
				T result = action.run();
				commit = true;
				return result;
			}
			catch (McpException e) {
				throw e;
			}
			catch (DuplicateNameException e) {
				throw McpException.conflict(e.getMessage());
			}
			catch (InvalidInputException | InvalidNameException | IllegalArgumentException e) {
				throw McpException.invalidParameter(e.getMessage());
			}
			catch (Exception e) {
				throw McpException.failed(transactionName + " failed: " + e.getMessage(), e);
			}
			finally {
				program.endTransaction(tx, commit);
			}
		});
	}
}
