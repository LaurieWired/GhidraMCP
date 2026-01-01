import requests
import json
import sys

GHIDRA_SERVER = "http://127.0.0.1:8089"
REQUEST_TIMEOUT = 120
function_address = "0x6fda2da0"

decompiler_comments = [
    {"address": "0x6fda2da6", "comment": "Validate node pointer is not NULL"},
    {"address": "0x6fda2db4", "comment": "Assertion failure - NULL node detected"},
    {"address": "0x6fda2dbe", "comment": "Terminate with error code -1"},
    {"address": "0x6fda2dc3", "comment": "Return field at offset +4 (node reference)"}
]

print("Checking server connectivity...")
try:
    response = requests.get(GHIDRA_SERVER + "/check_connection", timeout=5)
    if not response.ok:
        print("Error: Cannot connect to Ghidra MCP server")
        sys.exit(1)
    print("[OK] Connected to Ghidra: " + response.text + "
")
except requests.exceptions.RequestException as e:
    print("Error: Cannot connect to Ghidra MCP server: " + str(e))
    sys.exit(1)

print("="*60)
print("STEP 1: Adding decompiler comments")
print("="*60)

url = GHIDRA_SERVER + "/batch_set_comments"
payload = {
    "function_address": function_address,
    "decompiler_comments": decompiler_comments,
    "disassembly_comments": [],
    "plate_comment": None
}

print("Calling batch_set_comments for function " + function_address + "...")
print("Payload: " + json.dumps(payload, indent=2))

try:
    response = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    if response.ok:
        print("[OK] Success! Status code: " + str(response.status_code))
        print("
" + "="*60)
        print("RESULT FROM batch_set_comments:")
        print("="*60)
        try:
            parsed = json.loads(response.text)
            print(json.dumps(parsed, indent=2))
        except:
            print(response.text)
    else:
        print("[ERROR] Status code " + str(response.status_code))
        print("Response: " + response.text)
        sys.exit(1)
except requests.exceptions.RequestException as e:
    print("[ERROR] Request error: " + str(e))
    sys.exit(1)

print("
" + "="*60)
print("STEP 2: Verifying function completeness")
print("="*60)

url = GHIDRA_SERVER + "/analyze_function_completeness"
params = {"function_address": function_address}

print("Analyzing function completeness for " + function_address + "...")

try:
    response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
    if response.ok:
        analysis = json.loads(response.text)
        print("[OK] Completeness analysis received")
        
        print("
" + "="*60)
        print("COMPLETENESS ANALYSIS:")
        print("="*60)
        print(json.dumps(analysis, indent=2))

        score = analysis.get("completeness_score", 0)
        print("
" + "="*60)
        print("FINAL COMPLETENESS SCORE: " + str(score) + "%")
        print("="*60)

        if score >= 100:
            print("[OK] Function has reached 100% completeness!")
        else:
            print("[WARNING] Function completeness is " + str(score) + "% (target: 100%)")
            if "recommendations" in analysis:
                print("
Recommendations:")
                for rec in analysis["recommendations"]:
                    print("  - " + rec)
    else:
        print("[ERROR] Status code " + str(response.status_code))
        print("Response: " + response.text)
        sys.exit(1)
except requests.exceptions.RequestException as e:
    print("[ERROR] Request error: " + str(e))
    sys.exit(1)

print("
[OK] Script completed successfully!")
