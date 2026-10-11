package com.lauriewired.ghidramcp.core;

import java.util.List;

/**
 * Result types returned by {@link GhidraAnalysisService}. Serialized to JSON with snake_case names.
 */
public final class Model {

	private Model() {
	}

	public record FunctionRef(String name, String address) {
	}

	public record FunctionInfo(String name, String address, String signature, String namespace,
			String bodyStart, String bodyEnd, long bodySize, String callingConvention,
			boolean isThunk, boolean isExternal) {
	}

	public record ProgramInfo(String name, String projectPath, String executablePath,
			String executableFormat, String languageId, String compilerSpec, String processor,
			String endian, int pointerSize, String imageBase, String minAddress, String maxAddress,
			long memorySize, int functionCount, int externalFunctionCount,
			List<String> entryPoints, String md5,
			String sha256) {
	}

	public record Segment(String name, String start, String end, long size, String permissions,
			boolean initialized) {
	}

	public record SymbolRef(String name, String address, String namespace) {
	}

	public record DataItem(String address, String label, String type, String value) {
	}

	public record StringItem(String address, String value, String type, int length) {
	}

	public record Decompilation(FunctionRef function, String code, boolean truncated) {
	}

	public record InstructionLine(String address, String bytes, String instruction,
			String comment) {
	}

	public record XrefTo(String from, String type, FunctionRef fromFunction) {
	}

	public record XrefFrom(String to, String type, FunctionRef toFunction, String toLabel) {
	}

	public record Caller(String callSite, FunctionRef caller, String refType, boolean direct) {
	}

	public record Callee(String callSite, String target, String name, String refType,
			boolean direct, boolean external) {
	}

	public record FunctionCalls(FunctionRef function, Page<Caller> callers,
			Page<Callee> callees) {
	}

	public record MemoryGap(String start, String end, String reason) {
	}

	public record MemoryRead(String address, int length, String hex, String ascii,
			List<MemoryGap> gaps) {
	}

	public record Renamed(String address, String oldName, String newName) {
	}

	public record CommentSet(String address, String commentType, String comment) {
	}

	public record PrototypeSet(FunctionRef function, String signature) {
	}

	public record VariableTypeSet(FunctionRef function, String variable, String oldType,
			String newType) {
	}
}
