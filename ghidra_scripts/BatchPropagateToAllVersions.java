//Batch propagate documentation to all versions of the same binary in the project.
//Opens each matching program, runs hash-based propagation, saves, and closes.
//Skips the canonical source program (the one documentation is pulled from).
//@author GhidraMCP
//@category Documentation
//@keybinding
//@menupath Tools.3 - Batch Propagate To All Versions
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.data.*;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramDB;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * Batch propagates documentation from the hash index to ALL versions of a binary.
 * 
 * Usage:
 * 1. Run BuildHashIndex_Auto on your well-documented binary first
 * 2. Run this script - it will find all programs with the same filename
 * 3. Each matching program is opened, updated, saved, and closed
 * 
 * The script automatically skips:
 * - The canonical source program (where documentation came from)
 * - Programs that are already open (to avoid conflicts)
 */
public class BatchPropagateToAllVersions extends GhidraScript {

    // Path to the hash index file - must match BuildHashIndex_Auto
    private static final String INDEX_FILE = System.getProperty("user.home") +
        java.io.File.separator + "ghidra_function_hash_index.json";
    
    // Statistics
    private int programsFound = 0;
    private int programsProcessed = 0;
    private int programsSkipped = 0;
    private int totalFunctionsUpdated = 0;
    private int totalDataTypesCreated = 0;
    
    // Index data
    private Map<String, Map<String, Object>> functionsIndex;
    private Map<String, Map<String, Object>> dataTypesIndex;
    private Set<String> canonicalPaths = new HashSet<>();

    @Override
    protected void run() throws Exception {
        println("=".repeat(70));
        println("BATCH PROPAGATE TO ALL VERSIONS");
        println("=".repeat(70));
        println("Index file: " + INDEX_FILE);
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
        functionsIndex = functions;
        
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> dataTypes = (Map<String, Map<String, Object>>) index.get("data_types");
        dataTypesIndex = dataTypes != null ? dataTypes : new LinkedHashMap<>();
        
        println("  Loaded " + functionsIndex.size() + " unique hashes");
        println("  Loaded " + dataTypesIndex.size() + " data type definitions");
        println("");
        
        // Build set of canonical paths (sources we don't want to overwrite)
        for (Map<String, Object> hashEntry : functionsIndex.values()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> canonical = (Map<String, Object>) hashEntry.get("canonical");
            if (canonical != null) {
                String path = (String) canonical.get("program_path");
                if (path != null) {
                    canonicalPaths.add(path);
                }
            }
        }
        println("  Found " + canonicalPaths.size() + " canonical source paths to skip");
        println("");
        
        // Get current program name to find matching programs
        if (currentProgram == null) {
            printerr("No program is open! Open a program first to identify which binary to propagate.");
            return;
        }
        
        String targetName = currentProgram.getName();
        String currentPath = currentProgram.getDomainFile().getPathname();
        
        println("Looking for all '" + targetName + "' in the project...");
        println("Current program: " + currentPath);
        println("");
        
        // Get project and find all matching programs
        Project project = state.getProject();
        if (project == null) {
            printerr("No project is open!");
            return;
        }
        
        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();
        
        // Find all programs with matching name
        List<DomainFile> matchingPrograms = new ArrayList<>();
        findMatchingPrograms(rootFolder, targetName, matchingPrograms);
        
        programsFound = matchingPrograms.size();
        println("Found " + programsFound + " programs named '" + targetName + "'");
        println("");
        
        if (matchingPrograms.isEmpty()) {
            println("No matching programs found.");
            return;
        }
        
        // Process each matching program
        for (DomainFile domainFile : matchingPrograms) {
            if (monitor.isCancelled()) {
                println("Cancelled by user.");
                break;
            }
            
            String programPath = domainFile.getPathname();
            
            // Skip canonical sources
            if (canonicalPaths.contains(programPath)) {
                println("SKIP (canonical source): " + programPath);
                programsSkipped++;
                continue;
            }
            
            // Skip currently open program
            if (programPath.equals(currentPath)) {
                println("SKIP (currently open): " + programPath);
                programsSkipped++;
                continue;
            }
            
            // Process this program
            println("Processing: " + programPath);
            try {
                int[] stats = processProgram(domainFile);
                totalFunctionsUpdated += stats[0];
                totalDataTypesCreated += stats[1];
                programsProcessed++;
                println("  -> Updated " + stats[0] + " functions, created " + stats[1] + " data types");
            } catch (Exception e) {
                println("  ERROR: " + e.getMessage());
                programsSkipped++;
            }
        }
        
        // Summary
        println("");
        println("=".repeat(70));
        println("BATCH SUMMARY");
        println("=".repeat(70));
        println("Programs found: " + programsFound);
        println("Programs processed: " + programsProcessed);
        println("Programs skipped: " + programsSkipped);
        println("Total functions updated: " + totalFunctionsUpdated);
        println("Total data types created: " + totalDataTypesCreated);
    }

    /**
     * Recursively find all programs with matching name.
     */
    private void findMatchingPrograms(DomainFolder folder, String targetName, List<DomainFile> results) throws Exception {
        // Check files in this folder
        for (DomainFile file : folder.getFiles()) {
            if (file.getName().equals(targetName)) {
                results.add(file);
            }
        }
        
        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            findMatchingPrograms(subfolder, targetName, results);
        }
    }

    /**
     * Process a single program - open, propagate, save, close.
     * Returns [functionsUpdated, dataTypesCreated]
     */
    private int[] processProgram(DomainFile domainFile) throws Exception {
        int functionsUpdated = 0;
        int dataTypesCreated = 0;
        
        // Open the program
        Program program = (Program) domainFile.getDomainObject(this, true, false, monitor);
        
        try {
            String programPath = domainFile.getPathname();
            DataTypeManager dtm = program.getDataTypeManager();
            Map<String, DataType> createdDataTypes = new HashMap<>();
            
            // Start transaction
            int txId = program.startTransaction("Batch Propagate from Index");
            
            try {
                FunctionManager funcMgr = program.getFunctionManager();
                FunctionIterator funcIter = funcMgr.getFunctions(true);
                
                while (funcIter.hasNext() && !monitor.isCancelled()) {
                    Function func = funcIter.next();
                    
                    // Skip thunks and external
                    if (func.isThunk() || func.isExternal()) {
                        continue;
                    }
                    
                    // Compute hash
                    String hash = computeFunctionHash(func, program);
                    if (hash == null) continue;
                    
                    // Look up in index
                    Map<String, Object> hashEntry = functionsIndex.get(hash);
                    if (hashEntry == null) continue;
                    
                    @SuppressWarnings("unchecked")
                    Map<String, Object> canonical = (Map<String, Object>) hashEntry.get("canonical");
                    if (canonical == null) continue;
                    
                    // Find the best documented entry (canonical may be from old index without plate_comment/signature)
                    canonical = findBestDocumentedEntry(hashEntry, canonical);
                    
                    // Skip if canonical is this same program
                    String canonicalPath = (String) canonical.get("program_path");
                    if (programPath.equals(canonicalPath)) continue;
                    
                    // Skip if canonical is undocumented
                    Boolean hasCustomName = (Boolean) canonical.get("has_custom_name");
                    if (hasCustomName == null || !hasCustomName) continue;
                    
                    // Apply documentation
                    if (applyDocumentation(func, canonical, dtm, createdDataTypes)) {
                        functionsUpdated++;
                    }
                }
                
                dataTypesCreated = createdDataTypes.size();
                
                // Commit transaction
                program.endTransaction(txId, true);
                
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
            
            // Save the program
            domainFile.save(monitor);
            
        } finally {
            // Release/close the program
            program.release(this);
        }
        
        return new int[] { functionsUpdated, dataTypesCreated };
    }

    /**
     * Apply documentation to a function.
     */
    private boolean applyDocumentation(Function target, Map<String, Object> canonical,
                                        DataTypeManager dtm, Map<String, DataType> createdDataTypes) {
        boolean changed = false;
        
        try {
            // 1. Rename function
            String name = (String) canonical.get("name");
            if (name != null && !name.startsWith("FUN_")) {
                target.setName(name, SourceType.USER_DEFINED);
                changed = true;
            }
            
            // 2. Apply plate comment
            String plateComment = (String) canonical.get("plate_comment");
            if (plateComment != null && !plateComment.isEmpty()) {
                target.setComment(plateComment);
                changed = true;
            }
            
            // 3. Apply signature
            @SuppressWarnings("unchecked")
            Map<String, Object> signature = (Map<String, Object>) canonical.get("signature");
            if (signature != null) {
                if (applySignature(target, signature, dtm, createdDataTypes)) {
                    changed = true;
                }
            }
            
        } catch (Exception e) {
            // Continue with other functions
        }
        
        return changed;
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
     * Apply function signature.
     */
    private boolean applySignature(Function target, Map<String, Object> signature,
                                    DataTypeManager dtm, Map<String, DataType> createdDataTypes) {
        boolean changed = false;
        
        try {
            // Calling convention
            String callingConv = (String) signature.get("calling_convention");
            if (callingConv != null && !callingConv.equals("unknown")) {
                try {
                    target.setCallingConvention(callingConv);
                    changed = true;
                } catch (Exception e) { }
            }
            
            // Return type
            @SuppressWarnings("unchecked")
            Map<String, Object> returnTypeInfo = (Map<String, Object>) signature.get("return_type");
            if (returnTypeInfo != null) {
                DataType returnType = resolveOrCreateDataType(returnTypeInfo, dtm, createdDataTypes);
                if (returnType != null) {
                    target.setReturnType(returnType, SourceType.USER_DEFINED);
                    changed = true;
                }
            }
            
            // Parameters
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> params = (List<Map<String, Object>>) signature.get("parameters");
            if (params != null) {
                Parameter[] existingParams = target.getParameters();
                for (Map<String, Object> paramInfo : params) {
                    int ordinal = ((Number) paramInfo.get("ordinal")).intValue();
                    String paramName = (String) paramInfo.get("name");
                    
                    if (ordinal < existingParams.length) {
                        Parameter p = existingParams[ordinal];
                        
                        if (paramName != null && !paramName.startsWith("param_")) {
                            p.setName(paramName, SourceType.USER_DEFINED);
                            changed = true;
                        }
                        
                        @SuppressWarnings("unchecked")
                        Map<String, Object> typeInfo = (Map<String, Object>) paramInfo.get("type");
                        if (typeInfo != null) {
                            DataType paramType = resolveOrCreateDataType(typeInfo, dtm, createdDataTypes);
                            if (paramType != null) {
                                p.setDataType(paramType, SourceType.USER_DEFINED);
                                changed = true;
                            }
                        }
                    }
                }
            }
            
        } catch (Exception e) { }
        
        return changed;
    }

    /**
     * Resolve or create a data type.
     */
    private DataType resolveOrCreateDataType(Map<String, Object> typeInfo,
                                              DataTypeManager dtm, Map<String, DataType> cache) {
        if (typeInfo == null) return null;
        
        String name = (String) typeInfo.get("name");
        String path = (String) typeInfo.get("path");
        String kind = (String) typeInfo.get("kind");
        
        if (name == null || "undefined".equals(name)) return null;
        
        // Check cache
        if (path != null && cache.containsKey(path)) {
            return cache.get(path);
        }
        
        // Try to find existing
        if (path != null) {
            DataType existing = dtm.getDataType(path);
            if (existing != null) {
                cache.put(path, existing);
                return existing;
            }
        }
        
        // Search by name
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(name)) {
                if (path != null) cache.put(path, dt);
                return dt;
            }
        }
        
        // Handle pointer
        if ("pointer".equals(kind)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> pointedTo = (Map<String, Object>) typeInfo.get("pointed_to");
            DataType baseType = resolveOrCreateDataType(pointedTo, dtm, cache);
            if (baseType != null) {
                DataType ptr = dtm.getPointer(baseType);
                if (path != null) cache.put(path, ptr);
                return ptr;
            }
        }
        
        // Handle array
        if ("array".equals(kind)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> elemType = (Map<String, Object>) typeInfo.get("element_type");
            int count = ((Number) typeInfo.getOrDefault("element_count", 1)).intValue();
            DataType baseType = resolveOrCreateDataType(elemType, dtm, cache);
            if (baseType != null) {
                ArrayDataType arr = new ArrayDataType(baseType, count, baseType.getLength());
                if (path != null) cache.put(path, arr);
                return arr;
            }
        }
        
        // Handle struct/union/enum from index
        if (("struct".equals(kind) || "union".equals(kind) || "enum".equals(kind)) && path != null) {
            if (dataTypesIndex.containsKey(path)) {
                DataType created = createDataTypeFromIndex(path, dtm, cache);
                if (created != null) {
                    cache.put(path, created);
                    return created;
                }
            }
        }
        
        // Try primitive
        return findPrimitiveType(name);
    }

    /**
     * Create a data type from the index.
     */
    private DataType createDataTypeFromIndex(String path, DataTypeManager dtm, Map<String, DataType> cache) {
        Map<String, Object> dtDef = dataTypesIndex.get(path);
        if (dtDef == null) return null;
        
        String kind = (String) dtDef.get("kind");
        String name = (String) dtDef.get("name");
        String category = (String) dtDef.get("category");
        
        if (name == null) return null;
        
        try {
            CategoryPath catPath = new CategoryPath(category != null ? category : "/");
            
            if ("struct".equals(kind)) {
                int size = ((Number) dtDef.getOrDefault("size", 0)).intValue();
                StructureDataType struct = new StructureDataType(catPath, name, size, dtm);
                
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> fields = (List<Map<String, Object>>) dtDef.get("fields");
                if (fields != null) {
                    for (Map<String, Object> field : fields) {
                        int offset = ((Number) field.get("offset")).intValue();
                        String fieldName = (String) field.get("name");
                        int fieldSize = ((Number) field.getOrDefault("size", 4)).intValue();
                        String comment = (String) field.get("comment");
                        
                        @SuppressWarnings("unchecked")
                        Map<String, Object> fieldTypeInfo = (Map<String, Object>) field.get("type");
                        DataType fieldType = resolveOrCreateDataType(fieldTypeInfo, dtm, cache);
                        if (fieldType == null) fieldType = Undefined.getUndefinedDataType(fieldSize);
                        
                        try {
                            if (offset < struct.getLength()) {
                                struct.replaceAtOffset(offset, fieldType, fieldSize, fieldName, comment);
                            }
                        } catch (Exception e) { }
                    }
                }
                
                return dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
                
            } else if ("enum".equals(kind)) {
                int size = ((Number) dtDef.getOrDefault("size", 4)).intValue();
                EnumDataType enumDt = new EnumDataType(catPath, name, size, dtm);
                
                @SuppressWarnings("unchecked")
                Map<String, Object> values = (Map<String, Object>) dtDef.get("values");
                if (values != null) {
                    for (Map.Entry<String, Object> entry : values.entrySet()) {
                        enumDt.add(entry.getKey(), ((Number) entry.getValue()).longValue());
                    }
                }
                
                return dtm.addDataType(enumDt, DataTypeConflictHandler.REPLACE_HANDLER);
                
            } else if ("union".equals(kind)) {
                UnionDataType union = new UnionDataType(catPath, name, dtm);
                
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
                        Map<String, Object> fieldTypeInfo = (Map<String, Object>) field.get("type");
                        DataType fieldType = resolveOrCreateDataType(fieldTypeInfo, dtm, cache);
                        if (fieldType == null) fieldType = Undefined.getUndefinedDataType(fieldSize);
                        
                        union.add(fieldType, fieldName, comment);
                    }
                }
                
                return dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
            }
            
        } catch (Exception e) { }
        
        return null;
    }

    /**
     * Find a primitive type by name.
     */
    private DataType findPrimitiveType(String name) {
        switch (name) {
            case "int": return IntegerDataType.dataType;
            case "uint": return UnsignedIntegerDataType.dataType;
            case "char": return CharDataType.dataType;
            case "short": return ShortDataType.dataType;
            case "long": return LongDataType.dataType;
            case "float": return FloatDataType.dataType;
            case "double": return DoubleDataType.dataType;
            case "void": return VoidDataType.dataType;
            case "bool": return BooleanDataType.dataType;
            case "byte": return ByteDataType.dataType;
            case "word": return WordDataType.dataType;
            case "dword": return DWordDataType.dataType;
            case "qword": return QWordDataType.dataType;
            case "undefined": return Undefined.getUndefinedDataType(1);
            case "undefined1": return Undefined1DataType.dataType;
            case "undefined2": return Undefined2DataType.dataType;
            case "undefined4": return Undefined4DataType.dataType;
        }
        return null;
    }

    /**
     * Compute normalized function hash.
     */
    private String computeFunctionHash(Function func, Program program) {
        try {
            StringBuilder normalized = new StringBuilder();
            Listing listing = program.getListing();
            AddressSetView body = func.getBody();
            
            InstructionIterator instructions = listing.getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                
                normalized.append(instr.getMnemonicString());
                normalized.append(" ");
                
                int numOperands = instr.getNumOperands();
                for (int i = 0; i < numOperands; i++) {
                    Object[] opObjects = instr.getOpObjects(i);
                    for (Object obj : opObjects) {
                        if (obj instanceof Address) {
                            Address addr = (Address) obj;
                            if (body.contains(addr)) {
                                long offset = addr.subtract(func.getEntryPoint());
                                normalized.append("REL:").append(offset);
                            } else if (program.getFunctionManager().getFunctionAt(addr) != null) {
                                normalized.append("CALL_EXT");
                            } else {
                                normalized.append("DATA_EXT");
                            }
                        } else if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            long value = ((ghidra.program.model.scalar.Scalar) obj).getValue();
                            if (Math.abs(value) < 0x10000) {
                                normalized.append("IMM:").append(value);
                            } else {
                                normalized.append("IMM_LARGE");
                            }
                        } else if (obj instanceof Register) {
                            normalized.append("REG:").append(((Register) obj).getName());
                        }
                    }
                    normalized.append(",");
                }
                normalized.append(";");
            }
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.toString().getBytes());
            
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
        if (!file.exists()) return new LinkedHashMap<>();
        
        try {
            String content = new String(Files.readAllBytes(file.toPath()));
            return parseJson(content);
        } catch (Exception e) {
            println("  Warning: Could not load index: " + e.getMessage());
            return new LinkedHashMap<>();
        }
    }

    /**
     * Parse JSON using Gson.
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
}
