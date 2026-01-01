//[STEP 2] Propagate documentation from hash index to currently open program.
//Run BuildHashIndex_Auto first on your documented binary to build the index.
//Then run this script on undocumented binaries to apply matching documentation.
//Reads from: ghidra-mcp/function_hash_index.json
//@author GhidraMCP
//@category Documentation
//@keybinding
//@menupath Tools.2 - Propagate From Index (Auto)
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.data.*;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * Propagates function documentation from the hash index to the currently open program.
 * 
 * For each undocumented function (FUN_*) in the current program:
 * 1. Computes its normalized opcode hash
 * 2. Looks up the hash in the index
 * 3. If found, copies documentation from the canonical (best-documented) version
 * 
 * Documentation propagated includes:
 * - Function name
 * - Plate comment (function header)
 * - Return type and calling convention
 * - Parameter names and types
 * - Custom data types (structs, enums, typedefs)
 */
public class PropagateFromIndex_Auto extends GhidraScript {

    // Path to the hash index file - must match BuildHashIndex_Auto
    private static final String INDEX_FILE = System.getProperty("user.home") +
        java.io.File.separator + "ghidra_function_hash_index.json";
    
    // Statistics
    private int functionsScanned = 0;
    private int undocumentedFound = 0;
    private int matchesFound = 0;
    private int documentationApplied = 0;
    private int alreadyDocumented = 0;
    private int dataTypesCreated = 0;
    private int signaturesApplied = 0;
    private int plateCommentsApplied = 0;
    
    // Data type manager for creating types
    private DataTypeManager dtm;
    
    // Cache of created data types
    private Map<String, DataType> createdDataTypes = new HashMap<>();
    
    // Index data
    private Map<String, Map<String, Object>> dataTypesIndex;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program is open!");
            return;
        }
        
        dtm = currentProgram.getDataTypeManager();
        
        String programName = currentProgram.getName();
        String programPath = currentProgram.getDomainFile().getPathname();
        
        println("=".repeat(70));
        println("PROPAGATE DOCUMENTATION FROM INDEX (Enhanced)");
        println("=".repeat(70));
        println("Program: " + programName);
        println("Path: " + programPath);
        println("Index file: " + INDEX_FILE);
        println("");
        println("This version propagates: names, plate comments, signatures, and data types");
        println("");
        
        // Load index
        println("Loading hash index...");
        Map<String, Object> index = loadIndex();
        if (index.isEmpty()) {
            printerr("Index file not found or empty: " + INDEX_FILE);
            printerr("Run BuildHashIndex_Auto first on a documented binary.");
            return;
        }
        
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> functions = (Map<String, Map<String, Object>>) index.get("functions");
        if (functions == null || functions.isEmpty()) {
            printerr("No functions in index.");
            return;
        }
        
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> dataTypes = (Map<String, Map<String, Object>>) index.get("data_types");
        dataTypesIndex = dataTypes != null ? dataTypes : new LinkedHashMap<>();
        
        println("  Loaded " + functions.size() + " unique hashes from index");
        println("  Loaded " + dataTypesIndex.size() + " data type definitions");
        println("");
        
        // Find all functions and match against index
        println("Scanning all functions (including already documented)...");
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        
        // Collect matches first
        List<FunctionMatch> matches = new ArrayList<>();
        
        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            functionsScanned++;
            
            // Skip thunks and external functions
            if (func.isThunk() || func.isExternal()) {
                continue;
            }
            
            // Track if already documented (but still process it)
            boolean hasCustomName = !func.getName().startsWith("FUN_");
            if (hasCustomName) {
                alreadyDocumented++;
            } else {
                undocumentedFound++;
            }
            
            // Compute hash
            String hash = computeFunctionHash(func);
            if (hash == null) {
                continue;
            }
            
            // Look up in index
            Map<String, Object> hashEntry = functions.get(hash);
            if (hashEntry == null) {
                continue;
            }
            
            // Get canonical (best documented) version
            @SuppressWarnings("unchecked")
            Map<String, Object> canonical = (Map<String, Object>) hashEntry.get("canonical");
            if (canonical == null) {
                continue;
            }
            
            // Find the best documented entry (canonical may be from old index without plate_comment/signature)
            canonical = findBestDocumentedEntry(hashEntry, canonical);
            
            // Skip if canonical is from this same program (no point copying to itself)
            String canonicalPath = (String) canonical.get("program_path");
            if (programPath.equals(canonicalPath)) {
                continue;
            }
            
            // Skip if canonical is also undocumented
            Boolean hasCustom = (Boolean) canonical.get("has_custom_name");
            if (hasCustom == null || !hasCustom) {
                continue;
            }
            
            matchesFound++;
            matches.add(new FunctionMatch(func, canonical));
            
            if (functionsScanned % 500 == 0) {
                println("  Scanned " + functionsScanned + " functions...");
            }
        }
        
        println("  Found " + matchesFound + " matches to propagate");
        println("");
        
        if (matches.isEmpty()) {
            println("No documentation to propagate.");
            printSummary();
            return;
        }
        
        // Apply documentation in a single transaction
        println("Applying documentation...");
        int txId = currentProgram.startTransaction("Propagate Documentation from Index");
        
        try {
            for (FunctionMatch match : matches) {
                if (monitor.isCancelled()) break;
                
                applyDocumentation(match.function, match.canonical);
                documentationApplied++;
                
                if (documentationApplied % 100 == 0) {
                    println("  Applied " + documentationApplied + "/" + matches.size() + "...");
                }
            }
            
            currentProgram.endTransaction(txId, true);
            
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            throw e;
        }
        
        printSummary();
    }

    private void printSummary() {
        println("");
        println("=".repeat(70));
        println("SUMMARY");
        println("=".repeat(70));
        println("Functions scanned: " + functionsScanned);
        println("  - Already documented: " + alreadyDocumented);
        println("  - Undocumented (FUN_*): " + undocumentedFound);
        println("Matches found in index: " + matchesFound);
        println("Functions updated: " + documentationApplied);
        println("  - Plate comments applied: " + plateCommentsApplied);
        println("  - Signatures applied: " + signaturesApplied);
        println("  - Data types created: " + dataTypesCreated);
    }

    /**
     * Find the best documented entry from hashEntry (canonical or instances).
     * Some old index entries may have canonical without plate_comment/signature.
     */
    private Map<String, Object> findBestDocumentedEntry(Map<String, Object> hashEntry, Map<String, Object> canonical) {
        boolean canonicalHasPlate = canonical.containsKey("plate_comment") && canonical.get("plate_comment") != null;
        boolean canonicalHasSignature = canonical.containsKey("signature") && canonical.get("signature") != null;
        
        // If canonical is complete, use it
        if (canonicalHasPlate && canonicalHasSignature) {
            return canonical;
        }
        
        // Search instances for a better documented entry
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> instances = (List<Map<String, Object>>) hashEntry.get("instances");
        if (instances == null) {
            return canonical;
        }
        
        Map<String, Object> best = canonical;
        int bestScore = (canonicalHasPlate ? 1 : 0) + (canonicalHasSignature ? 1 : 0);
        
        for (Map<String, Object> inst : instances) {
            boolean hasPlate = inst.containsKey("plate_comment") && inst.get("plate_comment") != null;
            boolean hasSignature = inst.containsKey("signature") && inst.get("signature") != null;
            int score = (hasPlate ? 1 : 0) + (hasSignature ? 1 : 0);
            
            if (score > bestScore) {
                best = inst;
                bestScore = score;
            }
        }
        
        return best;
    }

    /**
     * Apply documentation from canonical entry to target function.
     */
    private void applyDocumentation(Function target, Map<String, Object> canonical) {
        try {
            // 1. Rename function
            String name = (String) canonical.get("name");
            if (name != null && !name.startsWith("FUN_")) {
                target.setName(name, SourceType.USER_DEFINED);
            }
            
            // 2. Apply plate comment
            String plateComment = (String) canonical.get("plate_comment");
            if (plateComment != null && !plateComment.isEmpty()) {
                target.setComment(plateComment);
                plateCommentsApplied++;
            }
            
            // 3. Apply signature (return type, calling convention, parameters)
            @SuppressWarnings("unchecked")
            Map<String, Object> signature = (Map<String, Object>) canonical.get("signature");
            if (signature != null) {
                applySignature(target, signature);
            }
            
        } catch (Exception e) {
            println("  Warning: Could not fully apply to " + target.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Apply function signature from the index.
     */
    private void applySignature(Function target, Map<String, Object> signature) {
        try {
            boolean changed = false;
            
            // Apply calling convention
            String callingConv = (String) signature.get("calling_convention");
            if (callingConv != null && !callingConv.equals("unknown")) {
                try {
                    target.setCallingConvention(callingConv);
                    changed = true;
                } catch (Exception e) {
                    // Calling convention might not be supported
                }
            }
            
            // Apply return type
            @SuppressWarnings("unchecked")
            Map<String, Object> returnTypeInfo = (Map<String, Object>) signature.get("return_type");
            if (returnTypeInfo != null) {
                DataType returnType = resolveOrCreateDataType(returnTypeInfo);
                if (returnType != null) {
                    target.setReturnType(returnType, SourceType.USER_DEFINED);
                    changed = true;
                }
            }
            
            // Apply parameters
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> params = (List<Map<String, Object>>) signature.get("parameters");
            if (params != null && !params.isEmpty()) {
                Parameter[] existingParams = target.getParameters();
                
                for (Map<String, Object> paramInfo : params) {
                    int ordinal = ((Number) paramInfo.get("ordinal")).intValue();
                    String paramName = (String) paramInfo.get("name");
                    @SuppressWarnings("unchecked")
                    Map<String, Object> typeInfo = (Map<String, Object>) paramInfo.get("type");
                    
                    if (ordinal < existingParams.length) {
                        Parameter existingParam = existingParams[ordinal];
                        
                        // Update parameter name if it's generic
                        if (paramName != null && !paramName.startsWith("param_")) {
                            existingParam.setName(paramName, SourceType.USER_DEFINED);
                            changed = true;
                        }
                        
                        // Update parameter type
                        if (typeInfo != null) {
                            DataType paramType = resolveOrCreateDataType(typeInfo);
                            if (paramType != null) {
                                existingParam.setDataType(paramType, SourceType.USER_DEFINED);
                                changed = true;
                            }
                        }
                    }
                }
            }
            
            if (changed) {
                signaturesApplied++;
            }
            
        } catch (Exception e) {
            // Signature application failed, but name/comment may have succeeded
        }
    }

    /**
     * Resolve a data type from the program or create it from the index.
     */
    private DataType resolveOrCreateDataType(Map<String, Object> typeInfo) {
        if (typeInfo == null) return null;
        
        String name = (String) typeInfo.get("name");
        String path = (String) typeInfo.get("path");
        String kind = (String) typeInfo.get("kind");
        
        if (name == null || "undefined".equals(name)) {
            return null;
        }
        
        // Check cache first
        if (path != null && createdDataTypes.containsKey(path)) {
            return createdDataTypes.get(path);
        }
        
        // Try to find existing type in program
        DataType existing = findExistingDataType(name, path);
        if (existing != null) {
            if (path != null) createdDataTypes.put(path, existing);
            return existing;
        }
        
        // Handle different type kinds
        if ("pointer".equals(kind)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> pointedTo = (Map<String, Object>) typeInfo.get("pointed_to");
            DataType baseType = resolveOrCreateDataType(pointedTo);
            if (baseType != null) {
                DataType ptrType = dtm.getPointer(baseType);
                if (path != null) createdDataTypes.put(path, ptrType);
                return ptrType;
            }
            return null;
        }
        
        if ("array".equals(kind)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> elementType = (Map<String, Object>) typeInfo.get("element_type");
            int count = ((Number) typeInfo.getOrDefault("element_count", 1)).intValue();
            DataType baseType = resolveOrCreateDataType(elementType);
            if (baseType != null) {
                ArrayDataType arrType = new ArrayDataType(baseType, count, baseType.getLength());
                if (path != null) createdDataTypes.put(path, arrType);
                return arrType;
            }
            return null;
        }
        
        if ("struct".equals(kind) || "union".equals(kind) || "enum".equals(kind)) {
            // Look up in data types index and create if needed
            if (path != null && dataTypesIndex.containsKey(path)) {
                DataType created = createDataTypeFromIndex(path);
                if (created != null) {
                    createdDataTypes.put(path, created);
                    return created;
                }
            }
        }
        
        if ("typedef".equals(kind)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> baseTypeInfo = (Map<String, Object>) typeInfo.get("base_type");
            DataType baseType = resolveOrCreateDataType(baseTypeInfo);
            if (baseType != null && name != null) {
                TypedefDataType td = new TypedefDataType(name, baseType);
                if (path != null) createdDataTypes.put(path, td);
                return td;
            }
        }
        
        // Try to find primitive type by name
        return findPrimitiveType(name);
    }

    /**
     * Find an existing data type in the program.
     */
    private DataType findExistingDataType(String name, String path) {
        if (path != null) {
            // Try exact path match
            DataType dt = dtm.getDataType(path);
            if (dt != null) return dt;
        }
        
        // Search by name
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(name)) {
                return dt;
            }
        }
        
        return null;
    }

    /**
     * Find a primitive/built-in data type.
     */
    private DataType findPrimitiveType(String name) {
        // Common primitive types
        switch (name) {
            case "int": return IntegerDataType.dataType;
            case "uint": return UnsignedIntegerDataType.dataType;
            case "char": return CharDataType.dataType;
            case "uchar": return UnsignedCharDataType.dataType;
            case "short": return ShortDataType.dataType;
            case "ushort": return UnsignedShortDataType.dataType;
            case "long": return LongDataType.dataType;
            case "ulong": return UnsignedLongDataType.dataType;
            case "longlong": return LongLongDataType.dataType;
            case "ulonglong": return UnsignedLongLongDataType.dataType;
            case "float": return FloatDataType.dataType;
            case "double": return DoubleDataType.dataType;
            case "void": return VoidDataType.dataType;
            case "bool": return BooleanDataType.dataType;
            case "byte": return ByteDataType.dataType;
            case "word": return WordDataType.dataType;
            case "dword": return DWordDataType.dataType;
            case "qword": return QWordDataType.dataType;
            case "pointer": return PointerDataType.dataType;
            case "undefined": return Undefined.getUndefinedDataType(1);
            case "undefined1": return Undefined1DataType.dataType;
            case "undefined2": return Undefined2DataType.dataType;
            case "undefined4": return Undefined4DataType.dataType;
            case "undefined8": return Undefined8DataType.dataType;
        }
        
        // Try searching in built-in types
        DataType builtIn = BuiltInDataTypeManager.getDataTypeManager().getDataType("/" + name);
        if (builtIn != null) return builtIn;
        
        return null;
    }

    /**
     * Create a data type from the index definition.
     */
    private DataType createDataTypeFromIndex(String path) {
        Map<String, Object> dtDef = dataTypesIndex.get(path);
        if (dtDef == null) return null;
        
        String kind = (String) dtDef.get("kind");
        String name = (String) dtDef.get("name");
        String category = (String) dtDef.get("category");
        
        if (name == null) return null;
        
        try {
            CategoryPath catPath = new CategoryPath(category != null ? category : "/");
            
            if ("struct".equals(kind)) {
                return createStructFromIndex(name, catPath, dtDef);
            } else if ("union".equals(kind)) {
                return createUnionFromIndex(name, catPath, dtDef);
            } else if ("enum".equals(kind)) {
                return createEnumFromIndex(name, catPath, dtDef);
            }
            
        } catch (Exception e) {
            println("  Warning: Could not create data type " + name + ": " + e.getMessage());
        }
        
        return null;
    }

    /**
     * Create a structure from index definition.
     */
    private DataType createStructFromIndex(String name, CategoryPath category, Map<String, Object> dtDef) throws Exception {
        int size = ((Number) dtDef.getOrDefault("size", 0)).intValue();
        
        StructureDataType struct = new StructureDataType(category, name, size, dtm);
        
        String desc = (String) dtDef.get("description");
        if (desc != null && !desc.isEmpty()) {
            struct.setDescription(desc);
        }
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> fields = (List<Map<String, Object>>) dtDef.get("fields");
        if (fields != null) {
            for (Map<String, Object> field : fields) {
                int offset = ((Number) field.get("offset")).intValue();
                String fieldName = (String) field.get("name");
                int fieldSize = ((Number) field.getOrDefault("size", 4)).intValue();
                String comment = (String) field.get("comment");
                
                @SuppressWarnings("unchecked")
                Map<String, Object> typeInfo = (Map<String, Object>) field.get("type");
                DataType fieldType = resolveOrCreateDataType(typeInfo);
                
                if (fieldType == null) {
                    fieldType = Undefined.getUndefinedDataType(fieldSize);
                }
                
                try {
                    if (offset < struct.getLength()) {
                        struct.replaceAtOffset(offset, fieldType, fieldSize, fieldName, comment);
                    }
                } catch (Exception e) {
                    // Field insertion failed, continue with others
                }
            }
        }
        
        // Add to program's data type manager
        DataType added = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
        dataTypesCreated++;
        return added;
    }

    /**
     * Create a union from index definition.
     */
    private DataType createUnionFromIndex(String name, CategoryPath category, Map<String, Object> dtDef) throws Exception {
        UnionDataType union = new UnionDataType(category, name, dtm);
        
        String desc = (String) dtDef.get("description");
        if (desc != null && !desc.isEmpty()) {
            union.setDescription(desc);
        }
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> fields = (List<Map<String, Object>>) dtDef.get("fields");
        if (fields != null) {
            for (Map<String, Object> field : fields) {
                String fieldName = (String) field.get("name");
                int fieldSize = ((Number) field.getOrDefault("size", 4)).intValue();
                String comment = (String) field.get("comment");
                
                @SuppressWarnings("unchecked")
                Map<String, Object> typeInfo = (Map<String, Object>) field.get("type");
                DataType fieldType = resolveOrCreateDataType(typeInfo);
                
                if (fieldType == null) {
                    fieldType = Undefined.getUndefinedDataType(fieldSize);
                }
                
                union.add(fieldType, fieldName, comment);
            }
        }
        
        DataType added = dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
        dataTypesCreated++;
        return added;
    }

    /**
     * Create an enum from index definition.
     */
    private DataType createEnumFromIndex(String name, CategoryPath category, Map<String, Object> dtDef) throws Exception {
        int size = ((Number) dtDef.getOrDefault("size", 4)).intValue();
        
        EnumDataType enumDt = new EnumDataType(category, name, size, dtm);
        
        String desc = (String) dtDef.get("description");
        if (desc != null && !desc.isEmpty()) {
            enumDt.setDescription(desc);
        }
        
        @SuppressWarnings("unchecked")
        Map<String, Object> values = (Map<String, Object>) dtDef.get("values");
        if (values != null) {
            for (Map.Entry<String, Object> entry : values.entrySet()) {
                String valueName = entry.getKey();
                long value = ((Number) entry.getValue()).longValue();
                enumDt.add(valueName, value);
            }
        }
        
        DataType added = dtm.addDataType(enumDt, DataTypeConflictHandler.REPLACE_HANDLER);
        dataTypesCreated++;
        return added;
    }

    /**
     * Compute a normalized opcode hash for a function.
     * Must match the algorithm in BuildHashIndex_Auto.
     */
    private String computeFunctionHash(Function func) {
        try {
            StringBuilder normalized = new StringBuilder();
            Listing listing = currentProgram.getListing();
            AddressSetView body = func.getBody();
            
            InstructionIterator instructions = listing.getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                
                // Get mnemonic (operation)
                normalized.append(instr.getMnemonicString());
                normalized.append(" ");
                
                // Normalize operands
                int numOperands = instr.getNumOperands();
                for (int i = 0; i < numOperands; i++) {
                    Object[] opObjects = instr.getOpObjects(i);
                    for (Object obj : opObjects) {
                        if (obj instanceof Address) {
                            Address addr = (Address) obj;
                            if (body.contains(addr)) {
                                // Internal reference - use relative offset
                                long offset = addr.subtract(func.getEntryPoint());
                                normalized.append("REL:").append(offset);
                            } else if (currentProgram.getFunctionManager().getFunctionAt(addr) != null) {
                                // External function call
                                normalized.append("CALL_EXT");
                            } else {
                                // External data reference
                                normalized.append("DATA_EXT");
                            }
                        } else if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            // Keep small immediates, normalize large ones
                            long value = ((ghidra.program.model.scalar.Scalar) obj).getValue();
                            if (Math.abs(value) < 0x10000) {
                                normalized.append("IMM:").append(value);
                            } else {
                                normalized.append("IMM_LARGE");
                            }
                        } else if (obj instanceof Register) {
                            // Keep register names
                            normalized.append("REG:").append(((Register) obj).getName());
                        }
                    }
                    normalized.append(",");
                }
                normalized.append(";");
            }
            
            // Compute SHA-256 hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.toString().getBytes());
            
            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
            
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Load index from file.
     */
    private Map<String, Object> loadIndex() {
        File file = new File(INDEX_FILE);
        if (!file.exists()) {
            return new LinkedHashMap<>();
        }
        
        try {
            String content = new String(Files.readAllBytes(file.toPath()));
            return parseJson(content);
        } catch (Exception e) {
            println("  Warning: Could not load index: " + e.getMessage());
            return new LinkedHashMap<>();
        }
    }

    /**
     * Parse JSON using Gson (available in Ghidra).
     */
    private Map<String, Object> parseJson(String json) {
        try {
            Class<?> gsonClass = Class.forName("com.google.gson.Gson");
            Object gson = gsonClass.getConstructor().newInstance();
            java.lang.reflect.Method fromJson = gsonClass.getMethod("fromJson", String.class, Class.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> result = (Map<String, Object>) fromJson.invoke(gson, json, Map.class);
            return result != null ? result : new LinkedHashMap<>();
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    /**
     * Helper class to track function matches.
     */
    private static class FunctionMatch {
        Function function;
        Map<String, Object> canonical;
        
        FunctionMatch(Function func, Map<String, Object> canonical) {
            this.function = func;
            this.canonical = canonical;
        }
    }
}
