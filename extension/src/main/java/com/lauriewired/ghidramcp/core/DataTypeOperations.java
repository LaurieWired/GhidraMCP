package com.lauriewired.ghidramcp.core;

import static com.lauriewired.ghidramcp.core.GhidraAnalysisService.parseAddress;
import static com.lauriewired.ghidramcp.core.GhidraAnalysisService.resolveDataType;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

import com.lauriewired.ghidramcp.core.GhidraAnalysisService.WriteExecutor;
import com.lauriewired.ghidramcp.core.Model.*;

import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.task.TaskMonitor;

/**
 * Creation, inspection, editing, and application of data types (structs, unions, enums, typedefs,
 * function definitions) in a program's data type manager.
 */
public class DataTypeOperations {

	public static final String DEFAULT_CATEGORY = "/ghidra-mcp";
	public static final int MAX_C_SOURCE_CHARS = 64 * 1024;
	public static final int MAX_FIELDS = 1000;
	public static final int MAX_DECLARATION_CHARS = 20_000;

	private static final Set<String> KINDS = Set.of("struct", "union", "enum", "typedef",
		"function", "pointer", "array", "builtin", "other");

	private static final Pattern PREPROCESSOR = Pattern.compile("(?m)^\\s*#\\s*\\w+");
	private static final CategoryPath PARSER_FUNCTIONS_CATEGORY = new CategoryPath("/functions");

	/** What to do when a type with the same name already exists in the target category. */
	public enum OnConflict {
		ERROR, REPLACE, KEEP;

		public static OnConflict parse(String value) {
			if (value == null || value.isEmpty()) {
				return ERROR;
			}
			try {
				return valueOf(value.toUpperCase(Locale.ROOT));
			}
			catch (IllegalArgumentException e) {
				throw McpException.invalidParameter(
					"on_conflict must be error, replace, or keep (got '" + value + "')");
			}
		}

		DataTypeConflictHandler handler() {
			return switch (this) {
				case ERROR -> DataTypeConflictHandler.DEFAULT_HANDLER;
				case REPLACE -> DataTypeConflictHandler.REPLACE_HANDLER;
				case KEEP -> DataTypeConflictHandler.KEEP_HANDLER;
			};
		}
	}

	@FunctionalInterface
	private interface Populator {
		void populate(DataType stored) throws Exception;
	}

	private final Transactions transactions;

	public DataTypeOperations(WriteExecutor writeExecutor) {
		this.transactions = new Transactions(writeExecutor);
	}

	// ------------------------------------------------------------------------------------------
	// Inspection
	// ------------------------------------------------------------------------------------------

	/** Lists data types; pointers and arrays are only included when asked for by kind. */
	public Page<DataTypeRef> listDataTypes(Program program, String filter, String category,
			String kind, int offset, int limit) {
		String needle = filter == null || filter.isEmpty() ? null : filter.toLowerCase(Locale.ROOT);
		String wantedKind = kind == null || kind.isEmpty() ? null : kind.toLowerCase(Locale.ROOT);
		if (wantedKind != null && !KINDS.contains(wantedKind)) {
			throw McpException.invalidParameter(
				"kind must be one of " + new TreeSet<>(KINDS) + " (got '" + kind + "')");
		}
		CategoryPath under = category == null || category.isEmpty() ? null : categoryPath(category);

		List<DataType> matches = new ArrayList<>();
		Iterator<DataType> it = program.getDataTypeManager().getAllDataTypes();
		while (it.hasNext()) {
			DataType dt = it.next();
			String k = kind(dt);
			boolean kindMatches = wantedKind != null ? k.equals(wantedKind)
					: !k.equals("pointer") && !k.equals("array");
			if (kindMatches && (under == null || dt.getCategoryPath().isAncestorOrSelf(under)) &&
				(needle == null || dt.getName().toLowerCase(Locale.ROOT).contains(needle))) {
				matches.add(dt);
			}
		}
		matches.sort(Comparator.comparing(DataType::getPathName));
		Page.Builder<DataTypeRef> page = new Page.Builder<>(offset, limit);
		for (DataType dt : matches) {
			page.offer(() -> ref(dt));
		}
		return page.build();
	}

	public DataTypeInfo getDataType(Program program, String name) {
		requireNonEmpty(name, "name");
		return info(program.getDataTypeManager(), resolveDataType(program, name));
	}

	public Page<String> listCategories(Program program, int offset, int limit) {
		List<String> paths = new ArrayList<>();
		collectCategories(program.getDataTypeManager().getRootCategory(), paths);
		paths.sort(null);
		return Page.of(paths, offset, limit);
	}

	private static void collectCategories(Category category, List<String> paths) {
		paths.add(category.getCategoryPathName());
		for (Category child : category.getCategories()) {
			collectCategories(child, paths);
		}
	}

	// ------------------------------------------------------------------------------------------
	// Creation
	// ------------------------------------------------------------------------------------------

	/**
	 * Parses C declarations into a scratch data type manager, then resolves every declared type
	 * into the program under {@code category}. Nothing is added to the program unless parsing
	 * succeeds and no conflict is rejected.
	 */
	public DataTypesDefined defineCTypes(Program program, String source, String category,
			String onConflict) {
		requireNonEmpty(source, "source");
		if (source.length() > MAX_C_SOURCE_CHARS) {
			throw McpException.invalidParameter(
				"source is limited to " + MAX_C_SOURCE_CHARS + " characters");
		}
		if (PREPROCESSOR.matcher(source).find()) {
			throw McpException.invalidParameter("The C preprocessor is not run: remove #include, " +
				"#define, and other # directives and declare the types you need directly");
		}
		OnConflict mode = OnConflict.parse(onConflict);
		CategoryPath target = categoryPath(category);
		DataTypeManager dtm = program.getDataTypeManager();

		try (StandAloneDataTypeManager scratch =
			new StandAloneDataTypeManager("ghidra-mcp", dtm.getDataOrganization())) {
			List<DataType> declared = parseInto(scratch, dtm, source, target);
			if (declared.isEmpty()) {
				throw McpException.invalidParameter("source does not declare any types");
			}
			return transactions.write(program, "Define C types", () -> {
				Set<String> existing = new HashSet<>();
				for (DataType dt : declared) {
					if (dtm.getDataType(dt.getCategoryPath(), dt.getName()) != null) {
						if (mode == OnConflict.ERROR) {
							throw McpException.conflict("Data type " + dt.getPathName() +
								" already exists; pass on_conflict=replace or keep");
						}
						existing.add(dt.getPathName());
					}
				}
				List<DataTypeRef> created = new ArrayList<>();
				List<DataTypeRef> replaced = new ArrayList<>();
				List<DataTypeRef> kept = new ArrayList<>();
				for (DataType dt : declared) {
					DataTypeRef resolved = ref(dtm.resolve(dt, mode.handler()));
					if (!existing.contains(dt.getPathName())) {
						created.add(resolved);
					}
					else if (mode == OnConflict.REPLACE) {
						replaced.add(resolved);
					}
					else {
						kept.add(resolved);
					}
				}
				return new DataTypesDefined(created, replaced, kept);
			});
		}
	}

	/** Parses source into scratch and returns the declared types, moved under target. */
	private static List<DataType> parseInto(StandAloneDataTypeManager scratch,
			DataTypeManager programDtm, String source, CategoryPath target) {
		int tx = scratch.startTransaction("Parse C source");
		try {
			CParser parser = new CParser(scratch, true, new DataTypeManager[] { programDtm });
			parser.parse(source);

			Set<DataType> declared = new LinkedHashSet<>(parser.getComposites().values());
			declared.addAll(parser.getEnums().values());
			declared.addAll(parser.getTypes().values());
			declared.addAll(parser.getFunctions().values());
			declared.addAll(undeclaredTypes(scratch, programDtm, declared));

			List<DataType> moved = new ArrayList<>();
			for (DataType dt : declared) {
				// "struct foo" naming a type that only exists in the program yields an empty
				// placeholder; point its uses at the program's type instead.
				DataType known = dt instanceof Composite && dt.isZeroLength()
						? GhidraAnalysisService.findByName(programDtm, dt.getName())
						: null;
				if (known instanceof Composite && !known.isZeroLength()) {
					scratch.replaceDataType(dt, scratch.resolve(known, null), false);
					continue;
				}
				CategoryPath path = dt.getCategoryPath();
				dt.setCategoryPath(path.isRoot() ? target : new CategoryPath(target, path.asList()));
				moved.add(dt);
			}
			return moved;
		}
		catch (ParseException e) {
			throw McpException.invalidParameter("Could not parse C source: " +
				e.getMessage().lines().findFirst().orElse(""));
		}
		catch (McpException e) {
			throw e;
		}
		catch (Exception e) {
			throw McpException.invalidParameter("Could not define C types: " + e.getMessage());
		}
		finally {
			scratch.endTransaction(tx, true);
		}
	}

	/**
	 * Types the parser created without reporting them, such as anonymous structs nested in a
	 * union. The parser creates types in the root and "/functions" categories; copies of program
	 * types it pulled in keep their own category, and unchanged root-level copies are skipped.
	 */
	private static List<DataType> undeclaredTypes(DataTypeManager scratch,
			DataTypeManager programDtm, Set<DataType> declared) {
		Set<String> declaredPaths = new HashSet<>();
		for (DataType dt : declared) {
			declaredPaths.add(dt.getPathName());
		}
		List<DataType> found = new ArrayList<>();
		Iterator<DataType> it = scratch.getAllDataTypes();
		while (it.hasNext()) {
			DataType dt = it.next();
			CategoryPath category = dt.getCategoryPath();
			if (!category.isRoot() && !category.equals(PARSER_FUNCTIONS_CATEGORY) ||
				declaredPaths.contains(dt.getPathName()) || dt instanceof BuiltInDataType ||
				dt instanceof Pointer || dt instanceof Array) {
				continue;
			}
			DataType original = programDtm.getDataType(dt.getDataTypePath());
			if (original == null || !original.isEquivalent(dt)) {
				found.add(dt);
			}
		}
		return found;
	}

	public DataTypeWritten createStruct(Program program, String name, String category,
			List<FieldSpec> fields, Integer size, boolean packingEnabled, String description,
			String onConflict) {
		CategoryPath cat = categoryPath(category);
		requireTypeName(name);
		if (packingEnabled && size != null) {
			throw McpException.invalidParameter("size cannot be used with packing enabled");
		}
		DataTypeManager dtm = program.getDataTypeManager();
		return create(program, "Create struct", new StructureDataType(cat, name, 0, dtm),
			onConflict, stored -> {
				Structure s = (Structure) stored;
				s.setDescription(description);
				s.setPackingEnabled(packingEnabled);
				if (size != null && size > s.getLength()) {
					s.growStructure(size - s.getLength());
				}
				for (FieldSpec field : fieldList(fields)) {
					addField(program, s, field);
				}
			});
	}

	public DataTypeWritten createUnion(Program program, String name, String category,
			List<FieldSpec> fields, String description, String onConflict) {
		CategoryPath cat = categoryPath(category);
		requireTypeName(name);
		DataTypeManager dtm = program.getDataTypeManager();
		return create(program, "Create union", new UnionDataType(cat, name, dtm), onConflict,
			stored -> {
				Union u = (Union) stored;
				u.setDescription(description);
				for (FieldSpec field : fieldList(fields)) {
					addField(program, u, field);
				}
			});
	}

	public DataTypeWritten createEnum(Program program, String name, String category,
			Map<String, Long> values, int size, String description, String onConflict) {
		CategoryPath cat = categoryPath(category);
		requireTypeName(name);
		if (size != 1 && size != 2 && size != 4 && size != 8) {
			throw McpException.invalidParameter("size must be 1, 2, 4, or 8 (got " + size + ")");
		}
		EnumDataType draft = new EnumDataType(cat, name, size, program.getDataTypeManager());
		draft.setDescription(description);
		try {
			if (values != null) {
				values.forEach(draft::add);
			}
		}
		catch (IllegalArgumentException e) {
			throw McpException.invalidParameter(e.getMessage());
		}
		return create(program, "Create enum", draft, onConflict, null);
	}

	public DataTypeWritten createTypedef(Program program, String name, String baseType,
			String category, String onConflict) {
		CategoryPath cat = categoryPath(category);
		requireTypeName(name);
		requireNonEmpty(baseType, "base_type");
		DataType base = resolveDataType(program, baseType);
		return create(program, "Create typedef",
			new TypedefDataType(cat, name, base, program.getDataTypeManager()), onConflict, null);
	}

	public DataTypeWritten createFunctionDefinition(Program program, String prototype,
			String category, String onConflict, DataTypeQueryService dataTypeService) {
		requireNonEmpty(prototype, "prototype");
		CategoryPath cat = categoryPath(category);
		FunctionDefinitionDataType draft;
		try {
			draft = new FunctionSignatureParser(program.getDataTypeManager(), dataTypeService)
					.parse(null, GhidraAnalysisService.normalizePrototype(prototype));
			draft.setCategoryPath(cat);
		}
		catch (Exception e) {
			throw McpException.invalidParameter(
				"Could not parse prototype '" + prototype + "': " + e.getMessage());
		}
		return create(program, "Create function definition", draft, onConflict, null);
	}

	/**
	 * Adds draft to the program (or replaces/keeps an existing type of the same name), then lets
	 * populate fill in the stored copy, so that fields can refer to the new type itself.
	 */
	private DataTypeWritten create(Program program, String transactionName, DataType draft,
			String onConflict, Populator populate) {
		OnConflict mode = OnConflict.parse(onConflict);
		DataTypeManager dtm = program.getDataTypeManager();
		return transactions.write(program, transactionName, () -> {
			DataType existing = dtm.getDataType(draft.getCategoryPath(), draft.getName());
			DataType stored;
			String action;
			if (existing == null) {
				stored = dtm.addDataType(draft, DataTypeConflictHandler.DEFAULT_HANDLER);
				action = "created";
			}
			else if (mode == OnConflict.KEEP) {
				return new DataTypeWritten("kept", info(dtm, existing));
			}
			else if (mode == OnConflict.REPLACE) {
				stored = dtm.replaceDataType(existing, draft, true);
				action = "replaced";
			}
			else {
				throw McpException.conflict("Data type " + existing.getPathName() +
					" already exists; pass on_conflict=replace or keep");
			}
			if (populate != null) {
				populate.populate(stored);
			}
			return new DataTypeWritten(action, info(dtm, stored));
		});
	}

	// ------------------------------------------------------------------------------------------
	// Editing
	// ------------------------------------------------------------------------------------------

	public DataTypeInfo addCompositeField(Program program, String compositeName, FieldSpec field) {
		Composite c = composite(program, compositeName);
		if (field == null) {
			throw McpException.missingParameter("field");
		}
		return transactions.write(program, "Add field", () -> {
			addField(program, c, field);
			return info(program.getDataTypeManager(), c);
		});
	}

	public DataTypeInfo updateCompositeField(Program program, String compositeName,
			Integer offset, String fieldName, String newName, String newType, String comment) {
		Composite c = composite(program, compositeName);
		if (newName == null && (newType == null || newType.isEmpty()) && comment == null) {
			throw McpException.missingParameter("new_name, new_type, or comment");
		}
		DataType type = newType == null || newType.isEmpty() ? null
				: resolveDataType(program, newType);
		return transactions.write(program, "Update field", () -> {
			DataTypeComponent comp = component(c, offset, fieldName);
			if (type != null) {
				int ordinal = comp.getOrdinal();
				String name = emptyToNull(newName != null ? newName : comp.getFieldName());
				String cmt = emptyToNull(comment != null ? comment : comp.getComment());
				if (c instanceof Structure s) {
					s.replace(ordinal, type, fieldLength(type), name, cmt);
				}
				else {
					c.delete(ordinal);
					c.insert(ordinal, type, fieldLength(type), name, cmt);
				}
			}
			else {
				if (newName != null) {
					comp.setFieldName(emptyToNull(newName));
				}
				if (comment != null) {
					comp.setComment(emptyToNull(comment));
				}
			}
			return info(program.getDataTypeManager(), c);
		});
	}

	/** Removes a field. In a non-packed struct the field's bytes become undefined. */
	public DataTypeInfo deleteCompositeField(Program program, String compositeName,
			Integer offset, String fieldName) {
		Composite c = composite(program, compositeName);
		return transactions.write(program, "Delete field", () -> {
			int ordinal = component(c, offset, fieldName).getOrdinal();
			if (c instanceof Structure s && !s.isPackingEnabled()) {
				s.clearComponent(ordinal);
			}
			else {
				c.delete(ordinal);
			}
			return info(program.getDataTypeManager(), c);
		});
	}

	public DataTypeInfo setEnumValue(Program program, String enumName, String name, long value,
			String comment) {
		requireNonEmpty(name, "value_name");
		Enum e = enumType(program, enumName);
		return transactions.write(program, "Set enum value", () -> {
			if (e.contains(name)) {
				e.remove(name);
			}
			e.add(name, value, emptyToNull(comment));
			return info(program.getDataTypeManager(), e);
		});
	}

	public DataTypeInfo deleteEnumValue(Program program, String enumName, String name) {
		requireNonEmpty(name, "value_name");
		Enum e = enumType(program, enumName);
		if (!e.contains(name)) {
			throw McpException.notFound("Enum " + e.getName() + " has no value named '" + name + "'");
		}
		return transactions.write(program, "Delete enum value", () -> {
			e.remove(name);
			return info(program.getDataTypeManager(), e);
		});
	}

	public DataTypeRenamed renameDataType(Program program, String name, String newName) {
		requireTypeName(newName);
		DataType dt = stored(program, name);
		String oldPath = dt.getPathName();
		return transactions.write(program, "Rename data type", () -> {
			dt.setName(newName);
			return new DataTypeRenamed(oldPath, ref(dt));
		});
	}

	/** Deletes a data type. Ghidra turns remaining uses of it into undefined bytes. */
	public DataTypeRef deleteDataType(Program program, String name) {
		DataType dt = stored(program, name);
		DataTypeRef ref = ref(dt);
		return transactions.write(program, "Delete data type", () -> {
			if (!program.getDataTypeManager().remove(dt)) {
				throw McpException.failed("Could not delete " + ref.path());
			}
			return ref;
		});
	}

	// ------------------------------------------------------------------------------------------
	// Application
	// ------------------------------------------------------------------------------------------

	/** Defines data of the given type at an address, optionally clearing data in the way. */
	public DataApplied applyDataType(Program program, String address, String typeName,
			boolean clearExisting) {
		requireNonEmpty(typeName, "type");
		Address addr = parseAddress(program, address);
		DataType dt = resolveDataType(program, typeName);
		return transactions.write(program, "Apply data type", () -> {
			if (!clearExisting && dt.getLength() > 0 &&
				!DataUtilities.isUndefinedRange(program, addr, addr.add(dt.getLength() - 1))) {
				throw McpException.invalidParameter("Defined data already exists in " + addr +
					".." + addr.add(dt.getLength() - 1) +
					" (pass clear_existing=true to replace existing data)");
			}
			Data data;
			try {
				data = DataUtilities.createData(program, addr, dt, -1,
					clearExisting ? DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
							: DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}
			catch (CodeUnitInsertionException e) {
				throw McpException.invalidParameter(e.getMessage() +
					(clearExisting ? "" : " (pass clear_existing=true to replace existing data)"));
			}
			Symbol label = program.getSymbolTable().getPrimarySymbol(addr);
			return new DataApplied(data.getAddress().toString(),
				data.getDataType().getDisplayName(), data.getLength(),
				label != null ? label.getName(true) : null);
		});
	}

	// ------------------------------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------------------------------

	private static void addField(Program program, Composite c, FieldSpec field)
			throws InvalidDataTypeException {
		requireNonEmpty(field.type(), "field type");
		DataType type = resolveDataType(program, field.type());
		String name = emptyToNull(field.name());
		String comment = emptyToNull(field.comment());
		Integer offset = field.offset();
		if (offset != null && offset < 0) {
			throw McpException.invalidParameter("field offset must not be negative");
		}

		if (c instanceof Union u) {
			if (offset != null && offset != 0) {
				throw McpException.invalidParameter("union fields are always at offset 0");
			}
			if (field.bitSize() != null) {
				u.addBitField(type, field.bitSize(), name, comment);
			}
			else {
				u.add(type, fieldLength(type), name, comment);
			}
			return;
		}

		Structure s = (Structure) c;
		if (s.isPackingEnabled() && offset != null) {
			throw McpException.invalidParameter(s.getName() + " has packing enabled, so field " +
				"offsets are computed by Ghidra; omit offset");
		}
		if (field.bitSize() != null) {
			if (s.isPackingEnabled()) {
				s.addBitField(type, field.bitSize(), name, comment);
			}
			else if (offset == null) {
				throw McpException.invalidParameter(
					"bit fields in a non-packed struct need an offset");
			}
			else {
				int bitOffset = field.bitOffset() != null ? field.bitOffset() : 0;
				s.insertBitFieldAt(offset, type.getLength(), bitOffset, type, field.bitSize(), name,
					comment);
			}
		}
		else if (offset == null) {
			s.add(type, fieldLength(type), name, comment);
		}
		else {
			int end = offset + fieldLength(type);
			if (end > s.getLength()) {
				s.growStructure(end - s.getLength());
			}
			s.replaceAtOffset(offset, type, fieldLength(type), name, comment);
		}
	}

	private static int fieldLength(DataType type) {
		if (type instanceof FunctionDefinition) {
			throw McpException.invalidParameter("A function definition cannot be a field; use a " +
				"pointer to it, e.g. '" + type.getName() + " *'");
		}
		if (type.getLength() <= 0) {
			throw McpException.invalidParameter(
				"Data type " + type.getName() + " has no fixed size and cannot be a field");
		}
		return type.getLength();
	}

	private static DataTypeComponent component(Composite c, Integer offset, String fieldName) {
		if (fieldName != null && !fieldName.isEmpty()) {
			for (DataTypeComponent comp : c.getDefinedComponents()) {
				String name = comp.getFieldName() != null ? comp.getFieldName()
						: comp.getDefaultFieldName();
				if (name.equals(fieldName)) {
					return comp;
				}
			}
			throw McpException.notFound("No field named '" + fieldName + "' in " + c.getName());
		}
		if (offset == null) {
			throw McpException.missingParameter("field_name or offset");
		}
		if (c instanceof Union) {
			throw McpException.invalidParameter("Identify union fields by field_name");
		}
		for (DataTypeComponent comp : c.getDefinedComponents()) {
			if (comp.getOffset() == offset) {
				return comp;
			}
		}
		throw McpException.notFound(
			"No field starts at offset " + offset + " (0x" + Integer.toHexString(offset) + ") in " +
				c.getName());
	}

	private static Composite composite(Program program, String name) {
		DataType dt = stored(program, name);
		if (!(dt instanceof Composite c)) {
			throw McpException.invalidParameter(dt.getName() + " is not a struct or union");
		}
		return c;
	}

	private static Enum enumType(Program program, String name) {
		DataType dt = stored(program, name);
		if (!(dt instanceof Enum e)) {
			throw McpException.invalidParameter(dt.getName() + " is not an enum");
		}
		return e;
	}

	/** A data type that is stored in the program, as opposed to a built-in or derived one. */
	private static DataType stored(Program program, String name) {
		requireNonEmpty(name, "name");
		DataType dt = resolveDataType(program, name);
		if (!program.getDataTypeManager().contains(dt) || dt instanceof BuiltInDataType) {
			throw McpException.invalidParameter(
				dt.getName() + " is a built-in or derived type and cannot be modified");
		}
		return dt;
	}

	private static CategoryPath categoryPath(String category) {
		if (category == null || category.isBlank()) {
			return new CategoryPath(DEFAULT_CATEGORY);
		}
		String path = category.trim();
		try {
			return new CategoryPath(path.startsWith("/") ? path : "/" + path);
		}
		catch (IllegalArgumentException e) {
			throw McpException.invalidParameter("Invalid category '" + category + "': " +
				e.getMessage());
		}
	}

	private static List<FieldSpec> fieldList(List<FieldSpec> fields) {
		return fields != null ? fields : List.of();
	}

	public static String kind(DataType dt) {
		if (dt instanceof Structure) {
			return "struct";
		}
		if (dt instanceof Union) {
			return "union";
		}
		if (dt instanceof Enum) {
			return "enum";
		}
		if (dt instanceof TypeDef) {
			return "typedef";
		}
		if (dt instanceof FunctionDefinition) {
			return "function";
		}
		if (dt instanceof Pointer) {
			return "pointer";
		}
		if (dt instanceof Array) {
			return "array";
		}
		if (dt instanceof BuiltInDataType) {
			return "builtin";
		}
		return "other";
	}

	private static DataTypeRef ref(DataType dt) {
		return new DataTypeRef(dt.getName(), dt.getPathName(), kind(dt), dt.getLength());
	}

	private static DataTypeInfo info(DataTypeManager dtm, DataType dt) {
		List<FieldInfo> fields = null;
		List<EnumValue> values = null;
		Boolean packing = null;
		String baseType = null;
		String prototype = null;
		boolean truncated = false;

		if (dt instanceof Composite c) {
			packing = c.isPackingEnabled();
			fields = new ArrayList<>();
			for (DataTypeComponent comp : c.getDefinedComponents()) {
				if (fields.size() >= MAX_FIELDS) {
					truncated = true;
					break;
				}
				fields.add(field(comp));
			}
		}
		else if (dt instanceof Enum e) {
			values = new ArrayList<>();
			for (String name : e.getNames()) {
				values.add(new EnumValue(name, e.getValue(name), e.getComment(name)));
			}
			values.sort(Comparator.comparingLong(EnumValue::value));
		}
		else if (dt instanceof TypeDef td) {
			baseType = td.getDataType().getDisplayName();
		}
		else if (dt instanceof Pointer p && p.getDataType() != null) {
			baseType = p.getDataType().getDisplayName();
		}
		else if (dt instanceof Array a) {
			baseType = a.getDataType().getDisplayName();
		}
		else if (dt instanceof FunctionDefinition fd) {
			prototype = fd.getPrototypeString();
		}

		String declaration = cDeclaration(dtm, dt);
		if (declaration != null && declaration.length() > MAX_DECLARATION_CHARS) {
			declaration = declaration.substring(0, MAX_DECLARATION_CHARS);
			truncated = true;
		}
		return new DataTypeInfo(dt.getName(), dt.getPathName(), kind(dt), dt.getLength(),
			dt.getAlignment(), packing, emptyToNull(dt.getDescription()), fields, values, baseType,
			prototype, declaration, truncated);
	}

	private static FieldInfo field(DataTypeComponent comp) {
		String name = comp.getFieldName() != null ? comp.getFieldName()
				: comp.getDefaultFieldName();
		if (comp.isBitFieldComponent() && comp.getDataType() instanceof BitFieldDataType bf) {
			return new FieldInfo(comp.getOrdinal(), comp.getOffset(), comp.getLength(), name,
				bf.getBaseDataType().getDisplayName(), comp.getComment(), bf.getDeclaredBitSize(),
				bf.getBitOffset());
		}
		return new FieldInfo(comp.getOrdinal(), comp.getOffset(), comp.getLength(), name,
			comp.getDataType().getDisplayName(), comp.getComment(), null, null);
	}

	/** The type (and the types it depends on) written as C, or null for built-in types. */
	private static String cDeclaration(DataTypeManager dtm, DataType dt) {
		if (dt instanceof BuiltInDataType || dt instanceof Pointer || dt instanceof Array) {
			return null;
		}
		StringWriter out = new StringWriter();
		try {
			new DataTypeWriter(dtm, out).write(List.of(dt), TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			return null;
		}
		String text = out.toString().strip();
		return text.isEmpty() ? null : text;
	}

	private static void requireTypeName(String name) {
		requireNonEmpty(name, "name");
		if (!DataUtilities.isValidDataTypeName(name)) {
			throw McpException.invalidParameter("'" + name + "' is not a valid data type name");
		}
	}

	private static void requireNonEmpty(String value, String name) {
		if (value == null || value.isEmpty()) {
			throw McpException.missingParameter(name);
		}
	}

	private static String emptyToNull(String value) {
		return value == null || value.isEmpty() ? null : value;
	}
}
