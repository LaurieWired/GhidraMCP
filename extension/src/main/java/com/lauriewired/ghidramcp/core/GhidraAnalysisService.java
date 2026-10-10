package com.lauriewired.ghidramcp.core;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.Supplier;

import com.lauriewired.ghidramcp.core.Model.*;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.*;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Analysis and annotation operations on an explicitly supplied {@link Program}. Has no
 * dependency on the Ghidra GUI, so it is shared by the GUI plugin and headless mode.
 */
public class GhidraAnalysisService {

	public static final int DECOMPILE_TIMEOUT_SECONDS = 60;
	public static final int MAX_DECOMPILE_CHARS = 200_000;
	public static final int MAX_READ_LENGTH = 4096;
	private static final int MAX_ENTRY_POINTS = 32;

	private static final Map<String, String> TYPE_ALIASES = Map.ofEntries(
		Map.entry("dword", "uint"), Map.entry("word", "ushort"), Map.entry("qword", "ulonglong"),
		Map.entry("__int64", "longlong"), Map.entry("unsigned __int64", "ulonglong"),
		Map.entry("boolean", "bool"), Map.entry("unsigned long", "ulong"),
		Map.entry("unsigned int", "uint"), Map.entry("unsigned short", "ushort"),
		Map.entry("unsigned char", "uchar"));

	/** Runs an action on the thread program writes must use. */
	public interface WriteExecutor {
		<T> T execute(Supplier<T> action);
	}

	@FunctionalInterface
	private interface WriteAction<T> {
		T run() throws Exception;
	}

	@FunctionalInterface
	private interface DecompiledAction<T> {
		T apply(DecompileResults results);
	}

	private final WriteExecutor writeExecutor;

	public GhidraAnalysisService(WriteExecutor writeExecutor) {
		this.writeExecutor = writeExecutor;
	}

	// ------------------------------------------------------------------------------------------
	// Program
	// ------------------------------------------------------------------------------------------

	public ProgramInfo getProgramInfo(Program program) {
		Language lang = program.getLanguage();
		List<String> entryPoints = new ArrayList<>();
		AddressIterator it = program.getSymbolTable().getExternalEntryPointIterator();
		while (it.hasNext() && entryPoints.size() < MAX_ENTRY_POINTS) {
			entryPoints.add(it.next().toString());
		}
		return new ProgramInfo(
			program.getName(),
			program.getDomainFile() != null ? program.getDomainFile().getPathname() : null,
			program.getExecutablePath(),
			program.getExecutableFormat(),
			lang.getLanguageID().toString(),
			program.getCompilerSpec().getCompilerSpecID().toString(),
			lang.getProcessor().toString(),
			lang.isBigEndian() ? "big" : "little",
			program.getDefaultPointerSize(),
			str(program.getImageBase()),
			str(program.getMinAddress()),
			str(program.getMaxAddress()),
			program.getMemory().getSize(),
			count(program.getFunctionManager().getFunctions(true)),
			count(program.getFunctionManager().getExternalFunctions()),
			entryPoints,
			program.getExecutableMD5(),
			program.getExecutableSHA256());
	}

	// ------------------------------------------------------------------------------------------
	// Listings
	// ------------------------------------------------------------------------------------------

	public Page<FunctionRef> listFunctions(Program program, String filter, int offset, int limit) {
		String needle = filter == null || filter.isEmpty() ? null : filter.toLowerCase(Locale.ROOT);
		Page.Builder<FunctionRef> page = new Page.Builder<>(offset, limit);
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			if (needle == null || f.getName(true).toLowerCase(Locale.ROOT).contains(needle)) {
				page.offer(() -> ref(f));
			}
		}
		return page.build();
	}

	public Page<String> listClasses(Program program, int offset, int limit) {
		TreeSet<String> names = new TreeSet<>();
		Iterator<GhidraClass> it = program.getSymbolTable().getClassNamespaces();
		while (it.hasNext()) {
			names.add(it.next().getName(true));
		}
		return Page.of(new ArrayList<>(names), offset, limit);
	}

	public Page<String> listNamespaces(Program program, int offset, int limit) {
		TreeSet<String> names = new TreeSet<>();
		SymbolTable table = program.getSymbolTable();
		for (Iterable<Symbol> symbols : List.of(table.getAllSymbols(true), table.getExternalSymbols())) {
			for (Symbol s : symbols) {
				for (Namespace ns = s.getParentNamespace(); ns != null && !ns.isGlobal();
						ns = ns.getParentNamespace()) {
					if (!(ns instanceof Function)) {
						names.add(ns.getName(true));
					}
				}
			}
		}
		return Page.of(new ArrayList<>(names), offset, limit);
	}

	public Page<Segment> listSegments(Program program, int offset, int limit) {
		Page.Builder<Segment> page = new Page.Builder<>(offset, limit);
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			page.offer(() -> new Segment(b.getName(), str(b.getStart()), str(b.getEnd()),
				b.getSize(), permissions(b), b.isInitialized()));
		}
		return page.build();
	}

	public Page<SymbolRef> listImports(Program program, int offset, int limit) {
		Page.Builder<SymbolRef> page = new Page.Builder<>(offset, limit);
		for (Symbol s : program.getSymbolTable().getExternalSymbols()) {
			page.offer(() -> new SymbolRef(s.getName(), str(s.getAddress()),
				s.getParentNamespace() != null ? s.getParentNamespace().getName() : null));
		}
		return page.build();
	}

	public Page<SymbolRef> listExports(Program program, int offset, int limit) {
		SymbolTable st = program.getSymbolTable();
		Page.Builder<SymbolRef> page = new Page.Builder<>(offset, limit);
		AddressIterator it = st.getExternalEntryPointIterator();
		while (it.hasNext()) {
			Address addr = it.next();
			page.offer(() -> {
				Symbol s = st.getPrimarySymbol(addr);
				return new SymbolRef(s != null ? s.getName() : null, str(addr),
					s != null && !s.getParentNamespace().isGlobal()
							? s.getParentNamespace().getName(true)
							: null);
			});
		}
		return page.build();
	}

	public Page<DataItem> listDefinedData(Program program, int offset, int limit) {
		Page.Builder<DataItem> page = new Page.Builder<>(offset, limit);
		DataIterator it = program.getListing().getDefinedData(true);
		while (it.hasNext()) {
			Data d = it.next();
			page.offer(() -> new DataItem(str(d.getAddress()), d.getLabel(),
				d.getDataType().getDisplayName(), d.getDefaultValueRepresentation()));
		}
		return page.build();
	}

	public Page<StringItem> listStrings(Program program, String filter, int offset, int limit) {
		String needle = filter == null || filter.isEmpty() ? null : filter.toLowerCase(Locale.ROOT);
		Page.Builder<StringItem> page = new Page.Builder<>(offset, limit);
		DataIterator it = program.getListing().getDefinedData(true);
		while (it.hasNext()) {
			Data d = it.next();
			if (!d.hasStringValue() || !(d.getValue() instanceof String value)) {
				continue;
			}
			if (needle == null || value.toLowerCase(Locale.ROOT).contains(needle)) {
				page.offer(() -> new StringItem(str(d.getAddress()), value,
					d.getDataType().getDisplayName(), d.getLength()));
			}
		}
		return page.build();
	}

	// ------------------------------------------------------------------------------------------
	// Functions
	// ------------------------------------------------------------------------------------------

	public FunctionInfo getFunction(Program program, String address) {
		return info(functionAt(program, address));
	}

	public FunctionInfo getFunctionContaining(Program program, Address address) {
		Function f = program.getFunctionManager().getFunctionContaining(address);
		if (f == null) {
			throw McpException.functionNotFound("containing " + address);
		}
		return info(f);
	}

	public Decompilation decompileByName(Program program, String name, TaskMonitor monitor) {
		return decompile(program, functionByName(program, name), monitor);
	}

	public Decompilation decompileByAddress(Program program, String address, TaskMonitor monitor) {
		return decompile(program, functionAt(program, address), monitor);
	}

	private Decompilation decompile(Program program, Function f, TaskMonitor monitor) {
		return withDecompiler(program, f, monitor, results -> {
			String code = results.getDecompiledFunction().getC();
			boolean truncated = code.length() > MAX_DECOMPILE_CHARS;
			if (truncated) {
				code = code.substring(0, MAX_DECOMPILE_CHARS);
			}
			return new Decompilation(ref(f), code, truncated);
		});
	}

	public Page<InstructionLine> disassemble(Program program, String address, int offset,
			int limit) {
		Function f = functionAt(program, address);
		Listing listing = program.getListing();
		Page.Builder<InstructionLine> page = new Page.Builder<>(offset, limit);
		InstructionIterator it = listing.getInstructions(f.getBody(), true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			page.offer(() -> new InstructionLine(str(ins.getAddress()), hexBytes(ins),
				ins.toString(), listing.getComment(CommentType.EOL, ins.getAddress())));
		}
		return page.build();
	}

	// ------------------------------------------------------------------------------------------
	// References
	// ------------------------------------------------------------------------------------------

	public Page<XrefTo> getXrefsTo(Program program, String address, int offset, int limit) {
		return xrefsTo(program, parseAddress(program, address), offset, limit);
	}

	public Page<XrefTo> getFunctionXrefs(Program program, String name, String address,
			int offset, int limit) {
		Function f = address != null && !address.isEmpty() ? functionAt(program, address)
				: functionByName(program, name);
		return xrefsTo(program, f.getEntryPoint(), offset, limit);
	}

	private Page<XrefTo> xrefsTo(Program program, Address addr, int offset, int limit) {
		FunctionManager fm = program.getFunctionManager();
		Page.Builder<XrefTo> page = new Page.Builder<>(offset, limit);
		for (Reference r : program.getReferenceManager().getReferencesTo(addr)) {
			page.offer(() -> new XrefTo(str(r.getFromAddress()), r.getReferenceType().getName(),
				refOrNull(fm.getFunctionContaining(r.getFromAddress()))));
		}
		return page.build();
	}

	public Page<XrefFrom> getXrefsFrom(Program program, String address, int offset, int limit) {
		Address addr = parseAddress(program, address);
		FunctionManager fm = program.getFunctionManager();
		Page.Builder<XrefFrom> page = new Page.Builder<>(offset, limit);
		for (Reference r : program.getReferenceManager().getReferencesFrom(addr)) {
			Address to = r.getToAddress();
			page.offer(() -> new XrefFrom(str(to), r.getReferenceType().getName(),
				refOrNull(fm.getFunctionAt(to)), labelAt(program, to)));
		}
		return page.build();
	}

	/**
	 * Callers and callees of a function, one level deep. Callees are found by walking the
	 * instructions of the function body, so non-contiguous bodies are handled correctly.
	 */
	public FunctionCalls getFunctionCalls(Program program, String address, String direction,
			int offset, int limit) {
		String dir = direction == null || direction.isEmpty() ? "both"
				: direction.toLowerCase(Locale.ROOT);
		if (!dir.equals("both") && !dir.equals("callers") && !dir.equals("callees")) {
			throw McpException.invalidParameter(
				"direction must be 'callers', 'callees', or 'both' (got '" + direction + "')");
		}
		Function f = functionAt(program, address);
		Page<Caller> callers = dir.equals("callees") ? null : callers(program, f, offset, limit);
		Page<Callee> callees = dir.equals("callers") ? null : callees(program, f, offset, limit);
		return new FunctionCalls(ref(f), callers, callees);
	}

	private Page<Caller> callers(Program program, Function f, int offset, int limit) {
		FunctionManager fm = program.getFunctionManager();
		Page.Builder<Caller> page = new Page.Builder<>(offset, limit);
		for (Reference r : program.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
			RefType type = r.getReferenceType();
			if (!type.isCall()) {
				continue;
			}
			page.offer(() -> new Caller(str(r.getFromAddress()),
				refOrNull(fm.getFunctionContaining(r.getFromAddress())), type.getName(),
				!type.isComputed()));
		}
		return page.build();
	}

	private Page<Callee> callees(Program program, Function f, int offset, int limit) {
		Listing listing = program.getListing();
		FunctionManager fm = program.getFunctionManager();
		Page.Builder<Callee> page = new Page.Builder<>(offset, limit);
		InstructionIterator it = listing.getInstructions(f.getBody(), true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			FlowType flow = ins.getFlowType();
			if (!flow.isCall()) {
				continue;
			}
			String callSite = str(ins.getAddress());
			boolean found = false;
			for (Reference r : ins.getReferencesFrom()) {
				RefType type = r.getReferenceType();
				if (type.isCall()) {
					found = true;
					Address to = r.getToAddress();
					Function target = fm.getFunctionAt(to);
					Function resolved = target != null && target.isThunk()
							? target.getThunkedFunction(true)
							: target;
					boolean external = r.isExternalReference() || to.isExternalAddress() ||
						(resolved != null && resolved.isExternal());
					page.offer(() -> new Callee(callSite, str(to),
						target != null ? target.getName(true) : labelAt(program, to),
						type.getName(), !type.isComputed() && !flow.isComputed(), external));
				}
			}
			if (found) {
				continue;
			}
			Callee viaPointer = calleeThroughPointer(program, ins, callSite, flow);
			page.offer(() -> viaPointer != null ? viaPointer
					: new Callee(callSite, null, null, flow.getName(), false, false));
		}
		return page.build();
	}

	/** Resolves calls like {@code call [IAT_entry]} through the pointer the operand reads. */
	private Callee calleeThroughPointer(Program program, Instruction ins, String callSite,
			FlowType flow) {
		ReferenceManager rm = program.getReferenceManager();
		for (Reference r : ins.getReferencesFrom()) {
			if (!r.getReferenceType().isData()) {
				continue;
			}
			for (Reference ptrRef : rm.getReferencesFrom(r.getToAddress())) {
				Address target = ptrRef.getToAddress();
				Function fn = program.getFunctionManager().getFunctionAt(target);
				String name = fn != null ? fn.getName(true) : labelAt(program, target);
				return new Callee(callSite, str(target), name, flow.getName(), false,
					ptrRef.isExternalReference() || target.isExternalAddress());
			}
		}
		return null;
	}

	// ------------------------------------------------------------------------------------------
	// Memory
	// ------------------------------------------------------------------------------------------

	public MemoryRead readMemory(Program program, String address, int length) {
		if (length < 1 || length > MAX_READ_LENGTH) {
			throw McpException.invalidParameter(
				"length must be between 1 and " + MAX_READ_LENGTH + " (got " + length + ")");
		}
		Address start = parseAddress(program, address);
		Memory memory = program.getMemory();
		StringBuilder hex = new StringBuilder();
		StringBuilder ascii = new StringBuilder();
		List<MemoryGap> gaps = new ArrayList<>();
		String gapReason = null;
		Address gapStart = null;
		Address prev = null;
		int read = 0;
		for (int i = 0; i < length; i++) {
			Address addr;
			try {
				addr = start.addNoWrap(i);
			}
			catch (Exception e) {
				break;
			}
			String reason = null;
			byte value = 0;
			MemoryBlock block = memory.getBlock(addr);
			if (block == null) {
				reason = "unmapped";
			}
			else if (!block.isInitialized()) {
				reason = "uninitialized";
			}
			else {
				try {
					value = memory.getByte(addr);
				}
				catch (MemoryAccessException e) {
					reason = "unreadable";
				}
			}
			if (!java.util.Objects.equals(reason, gapReason)) {
				if (gapReason != null) {
					gaps.add(new MemoryGap(str(gapStart), str(prev), gapReason));
				}
				gapReason = reason;
				gapStart = addr;
			}
			if (hex.length() > 0) {
				hex.append(' ');
			}
			if (reason == null) {
				hex.append(String.format("%02x", value & 0xff));
				ascii.append(value >= 0x20 && value < 0x7f ? (char) value : '.');
			}
			else {
				hex.append("??");
				ascii.append(' ');
			}
			prev = addr;
			read++;
		}
		if (gapReason != null) {
			gaps.add(new MemoryGap(str(gapStart), str(prev), gapReason));
		}
		return new MemoryRead(str(start), read, hex.toString(), ascii.toString(), gaps);
	}

	// ------------------------------------------------------------------------------------------
	// Modifications
	// ------------------------------------------------------------------------------------------

	public Renamed renameFunctionByName(Program program, String oldName, String newName) {
		return renameFunction(program, functionByName(program, oldName), newName);
	}

	public Renamed renameFunctionByAddress(Program program, String address, String newName) {
		return renameFunction(program, functionAt(program, address), newName);
	}

	private Renamed renameFunction(Program program, Function f, String newName) {
		requireNonEmpty(newName, "new_name");
		return write(program, "Rename function", () -> {
			String old = f.getName();
			f.setName(newName, SourceType.USER_DEFINED);
			return new Renamed(str(f.getEntryPoint()), old, f.getName());
		});
	}

	public Renamed renameData(Program program, String address, String newName) {
		requireNonEmpty(newName, "new_name");
		Address addr = parseAddress(program, address);
		SymbolTable st = program.getSymbolTable();
		Data data = program.getListing().getDefinedDataAt(addr);
		Symbol existing = st.getPrimarySymbol(addr);
		if (data == null && existing == null) {
			throw McpException.notFound("No defined data or symbol at " + addr);
		}
		return write(program, "Rename data", () -> {
			Symbol symbol = st.getPrimarySymbol(addr);
			String old = symbol != null ? symbol.getName() : null;
			if (symbol != null) {
				symbol.setName(newName, SourceType.USER_DEFINED);
			}
			else {
				symbol = st.createLabel(addr, newName, SourceType.USER_DEFINED);
			}
			return new Renamed(str(addr), old, symbol.getName());
		});
	}

	public Renamed renameVariable(Program program, String functionName, String functionAddress,
			String oldName, String newName, TaskMonitor monitor) {
		requireNonEmpty(oldName, "old_name");
		requireNonEmpty(newName, "new_name");
		Function f = functionByNameOrAddress(program, functionName, functionAddress);
		return withDecompiler(program, f, monitor, results -> {
			HighFunction hf = highFunction(results);
			HighSymbol target = null;
			Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
			while (it.hasNext()) {
				HighSymbol s = it.next();
				if (s.getName().equals(newName)) {
					throw McpException.conflict(
						"A variable named '" + newName + "' already exists in " + f.getName());
				}
				if (s.getName().equals(oldName)) {
					target = s;
				}
			}
			if (target == null) {
				throw McpException.notFound(
					"Variable '" + oldName + "' not found in " + f.getName());
			}
			HighSymbol symbol = target;
			boolean fullCommit = checkFullCommit(symbol, hf);
			return write(program, "Rename variable", () -> {
				if (fullCommit) {
					HighFunctionDBUtil.commitParamsToDatabase(hf, false,
						ReturnCommitOption.NO_COMMIT, f.getSignatureSource());
				}
				HighFunctionDBUtil.updateDBVariable(symbol, newName, null,
					SourceType.USER_DEFINED);
				return new Renamed(str(f.getEntryPoint()), oldName, newName);
			});
		});
	}

	public VariableTypeSet setLocalVariableType(Program program, String functionAddress,
			String variableName, String typeName, TaskMonitor monitor) {
		requireNonEmpty(variableName, "variable_name");
		requireNonEmpty(typeName, "new_type");
		Function f = functionAt(program, functionAddress);
		DataType type = resolveDataType(program, typeName);
		return withDecompiler(program, f, monitor, results -> {
			HighFunction hf = highFunction(results);
			HighSymbol symbol = null;
			Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
			while (it.hasNext() && symbol == null) {
				HighSymbol s = it.next();
				if (s.getName().equals(variableName)) {
					symbol = s;
				}
			}
			if (symbol == null) {
				throw McpException.notFound(
					"Variable '" + variableName + "' not found in " + f.getName());
			}
			HighSymbol target = symbol;
			String oldType = target.getDataType() != null ? target.getDataType().getDisplayName()
					: null;
			boolean fullCommit = checkFullCommit(target, hf);
			return write(program, "Set variable type", () -> {
				if (fullCommit) {
					HighFunctionDBUtil.commitParamsToDatabase(hf, false,
						ReturnCommitOption.NO_COMMIT, f.getSignatureSource());
				}
				HighFunctionDBUtil.updateDBVariable(target, null, type, SourceType.USER_DEFINED);
				return new VariableTypeSet(ref(f), variableName, oldType, type.getDisplayName());
			});
		});
	}

	public PrototypeSet setFunctionPrototype(Program program, String functionAddress,
			String prototype, DataTypeQueryService dataTypeService, TaskMonitor monitor) {
		requireNonEmpty(prototype, "prototype");
		Function f = functionAt(program, functionAddress);
		FunctionDefinitionDataType signature;
		try {
			signature = new FunctionSignatureParser(program.getDataTypeManager(), dataTypeService)
					.parse(f.getSignature(), prototype);
		}
		catch (Exception e) {
			throw McpException.invalidParameter(
				"Could not parse prototype '" + prototype + "': " + e.getMessage());
		}
		return write(program, "Set function prototype", () -> {
			ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(f.getEntryPoint(),
				signature, SourceType.USER_DEFINED, false, false,
				DataTypeConflictHandler.DEFAULT_HANDLER, FunctionRenameOption.RENAME);
			if (!cmd.applyTo(program, monitor)) {
				throw McpException.failed("Could not apply prototype: " + cmd.getStatusMsg());
			}
			return new PrototypeSet(ref(f), f.getSignature().getPrototypeString());
		});
	}

	public CommentSet setComment(Program program, String address, String comment,
			CommentType type) {
		if (comment == null) {
			throw McpException.missingParameter("comment");
		}
		Address addr = parseAddress(program, address);
		return write(program, "Set " + type.name().toLowerCase(Locale.ROOT) + " comment", () -> {
			program.getListing().setComment(addr, type, comment.isEmpty() ? null : comment);
			return new CommentSet(str(addr), type.name(),
				program.getListing().getComment(type, addr));
		});
	}

	// ------------------------------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------------------------------

	public static Address parseAddress(Program program, String text) {
		if (text == null || text.isBlank()) {
			throw McpException.missingParameter("address");
		}
		Address addr;
		try {
			addr = program.getAddressFactory().getAddress(text.trim());
		}
		catch (Exception e) {
			addr = null;
		}
		if (addr == null) {
			throw McpException.badAddress(text);
		}
		return addr;
	}

	/** The function at or containing the given address. */
	public static Function functionAt(Program program, String address) {
		Address addr = parseAddress(program, address);
		FunctionManager fm = program.getFunctionManager();
		Function f = fm.getFunctionAt(addr);
		if (f == null) {
			f = fm.getFunctionContaining(addr);
		}
		if (f == null) {
			throw McpException.functionNotFound("at or containing " + addr);
		}
		return f;
	}

	/** The unique function with the given simple or namespace-qualified name. */
	public static Function functionByName(Program program, String name) {
		if (name == null || name.isEmpty()) {
			throw McpException.missingParameter("name");
		}
		List<Function> matches = new ArrayList<>();
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			if (f.getName().equals(name) || f.getName(true).equals(name)) {
				matches.add(f);
			}
		}
		if (matches.isEmpty()) {
			throw McpException.functionNotFound("named '" + name + "'");
		}
		if (matches.size() > 1) {
			List<String> where = new ArrayList<>();
			for (Function f : matches) {
				where.add(f.getName(true) + " @ " + f.getEntryPoint());
			}
			throw McpException.ambiguous("'" + name + "' matches " + matches.size() +
				" functions; use the address-based tool instead: " + String.join(", ", where));
		}
		return matches.get(0);
	}

	private static Function functionByNameOrAddress(Program program, String name,
			String address) {
		if (address != null && !address.isEmpty()) {
			return functionAt(program, address);
		}
		return functionByName(program, name);
	}

	private <T> T write(Program program, String transactionName, WriteAction<T> action) {
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
			catch (InvalidInputException e) {
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

	private static <T> T withDecompiler(Program program, Function f, TaskMonitor monitor,
			DecompiledAction<T> action) {
		DecompInterface decomp = new DecompInterface();
		try {
			if (!decomp.openProgram(program)) {
				throw McpException.decompileFailed(
					"Decompiler could not open program: " + decomp.getLastMessage());
			}
			DecompileResults results =
				decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor);
			if (results == null || !results.decompileCompleted()) {
				String why = results != null ? results.getErrorMessage() : "no result";
				throw McpException.decompileFailed(
					"Decompilation of " + f.getName() + " failed: " + why);
			}
			return action.apply(results);
		}
		finally {
			decomp.dispose();
		}
	}

	private static HighFunction highFunction(DecompileResults results) {
		HighFunction hf = results.getHighFunction();
		if (hf == null || hf.getLocalSymbolMap() == null) {
			throw McpException.decompileFailed("Decompiler produced no high function");
		}
		return hf;
	}

	/**
	 * Copied from AbstractDecompilerAction.checkFullCommit (protected there). Returns true if the
	 * decompiler's view of the prototype differs from the database, in which case parameters must
	 * be committed before a parameter symbol can be modified.
	 */
	private static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}
		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Resolves C-style type names (including pointers and arrays), names from any category of the
	 * program's data type manager, a few Windows aliases, and Windows "P" pointer typedef names.
	 */
	public static DataType resolveDataType(Program program, String typeName) {
		DataTypeManager dtm = program.getDataTypeManager();
		String name = typeName.trim();

		DataType dt = parseDataType(dtm, name);
		if (dt == null) {
			dt = findByName(dtm, name);
		}
		if (dt == null && TYPE_ALIASES.containsKey(name.toLowerCase(Locale.ROOT))) {
			dt = parseDataType(dtm, TYPE_ALIASES.get(name.toLowerCase(Locale.ROOT)));
		}
		if (dt == null && name.length() > 1 && name.startsWith("P") &&
			Character.isUpperCase(name.charAt(1))) {
			String base = name.substring(1);
			DataType baseType = base.equals("VOID") ? parseDataType(dtm, "void")
					: findByName(dtm, base);
			if (baseType != null) {
				dt = new PointerDataType(baseType, dtm);
			}
		}
		if (dt == null) {
			throw McpException.notFound("Data type not found: " + typeName);
		}
		return dt;
	}

	private static DataType parseDataType(DataTypeManager dtm, String name) {
		try {
			return new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL).parse(name);
		}
		catch (Exception e) {
			return null;
		}
	}

	private static DataType findByName(DataTypeManager dtm, String name) {
		DataType caseInsensitive = null;
		Iterator<DataType> it = dtm.getAllDataTypes();
		while (it.hasNext()) {
			DataType dt = it.next();
			if (dt.getName().equals(name)) {
				return dt;
			}
			if (caseInsensitive == null && dt.getName().equalsIgnoreCase(name)) {
				caseInsensitive = dt;
			}
		}
		return caseInsensitive;
	}

	private static void requireNonEmpty(String value, String name) {
		if (value == null || value.isEmpty()) {
			throw McpException.missingParameter(name);
		}
	}

	public static FunctionRef ref(Function f) {
		return new FunctionRef(f.getName(true), str(f.getEntryPoint()));
	}

	private static FunctionRef refOrNull(Function f) {
		return f != null ? ref(f) : null;
	}

	private static FunctionInfo info(Function f) {
		return new FunctionInfo(f.getName(), str(f.getEntryPoint()),
			f.getSignature().getPrototypeString(), f.getParentNamespace().getName(true),
			str(f.getBody().getMinAddress()), str(f.getBody().getMaxAddress()),
			f.getBody().getNumAddresses(), f.getCallingConventionName(), f.isThunk(),
			f.isExternal());
	}

	private static String labelAt(Program program, Address addr) {
		Symbol s = program.getSymbolTable().getPrimarySymbol(addr);
		return s != null ? s.getName(true) : null;
	}

	private static String permissions(MemoryBlock b) {
		return (b.isRead() ? "r" : "-") + (b.isWrite() ? "w" : "-") + (b.isExecute() ? "x" : "-");
	}

	private static String hexBytes(Instruction ins) {
		try {
			byte[] bytes = ins.getBytes();
			StringBuilder sb = new StringBuilder(bytes.length * 2);
			for (byte b : bytes) {
				sb.append(String.format("%02x", b & 0xff));
			}
			return sb.toString();
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	private static String str(Address addr) {
		return addr != null ? addr.toString() : null;
	}

	private static int count(Iterable<?> items) {
		int n = 0;
		for (Object ignored : items) {
			n++;
		}
		return n;
	}
}
