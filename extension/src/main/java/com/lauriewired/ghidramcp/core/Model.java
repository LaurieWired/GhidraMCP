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

	public record DataTypeRef(String name, String path, String kind, int size) {
	}

	public record FieldInfo(int ordinal, int offset, int length, String name, String type,
			String comment, Integer bitSize, Integer bitOffset) {
	}

	public record EnumValue(String name, long value, String comment) {
	}

	public record DataTypeInfo(String name, String path, String kind, int size, int alignment,
			Boolean packingEnabled, String description, List<FieldInfo> fields,
			List<EnumValue> values, String baseType, String prototype, String cDeclaration,
			boolean truncated) {
	}

	public record DataTypeWritten(String action, DataTypeInfo dataType) {
	}

	public record DataTypesDefined(List<DataTypeRef> created, List<DataTypeRef> replaced,
			List<DataTypeRef> kept) {
	}

	public record DataTypeRenamed(String oldPath, DataTypeRef dataType) {
	}

	public record DataApplied(String address, String type, int length, String label) {
	}

	/** A struct or union field as supplied by the client. */
	public record FieldSpec(String name, String type, Integer offset, String comment,
			Integer bitSize, Integer bitOffset) {
	}
}
