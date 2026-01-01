#!/usr/bin/env python3
"""
Run FixFunctionParametersHeadless via Ghidra Headless Analyzer

This script executes the headless version of FixFunctionParameters
using Ghidra's analyzeHeadless command for batch processing.
"""

import subprocess
import sys
import os
import time
from pathlib import Path

def find_ghidra_installation():
    """Find Ghidra installation directory"""
    # Common installation paths
    common_paths = [
        r"C:\ghidra_11.2.1_PUBLIC",
        r"C:\ghidra_11.2_PUBLIC",
        r"C:\ghidra_11.1.2_PUBLIC",
        r"C:\Program Files\ghidra_11.2.1_PUBLIC",
        r"C:\Users\benam\tools\ghidra_11.2.1_PUBLIC",
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            return path
    
    # Try to find from environment
    ghidra_home = os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_home and os.path.exists(ghidra_home):
        return ghidra_home
    
    return None

def run_headless_fix(ghidra_path, project_path, project_name, analyze_only=False):
    """
    Run FixFunctionParametersHeadless via Ghidra headless analyzer
    
    Args:
        ghidra_path: Path to Ghidra installation
        project_path: Path to Ghidra project directory
        project_name: Name of the Ghidra project
        analyze_only: If True, run in analyze-only mode (no changes)
    
    Returns:
        Exit code (0 = success)
    """
    
    # Construct analyzeHeadless command
    analyze_headless = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
    
    if not os.path.exists(analyze_headless):
        print(f"ERROR: analyzeHeadless.bat not found at {analyze_headless}")
        return 1
    
    # Build command
    cmd = [
        analyze_headless,
        project_path,           # Project directory
        project_name,           # Project name
        "-process",             # Process existing program
        "-noanalysis",          # Don't re-run auto-analysis
        "-scriptPath", r"C:\Users\benam\ghidra_scripts",  # Script directory
        "-postScript", "FixFunctionParametersHeadless.java",  # Script to run
    ]
    
    # Add analyze-only flag if requested
    if analyze_only:
        cmd.extend(["-scriptArg", "--analyze-only"])
    
    print("=" * 60)
    print("GHIDRA HEADLESS FIX EXECUTION")
    print("=" * 60)
    print(f"Ghidra: {ghidra_path}")
    print(f"Project: {project_path}/{project_name}")
    print(f"Script: FixFunctionParametersHeadless.java")
    print(f"Mode: {'Analyze Only' if analyze_only else 'Apply Fixes'}")
    print()
    print("Command:")
    print(" ".join(cmd))
    print()
    print("Starting execution...")
    print("=" * 60)
    print()
    
    start_time = time.time()
    
    try:
        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900  # 15 minute timeout
        )
        
        elapsed = time.time() - start_time
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        print()
        print("=" * 60)
        print(f"Execution completed in {elapsed:.1f} seconds")
        print(f"Exit code: {result.returncode}")
        print("=" * 60)
        
        return result.returncode
        
    except subprocess.TimeoutExpired:
        print("ERROR: Script execution timed out after 15 minutes")
        return 1
    except Exception as e:
        print(f"ERROR: {e}")
        return 1

def main():
    """Main entry point"""
    
    # Check for analyze-only flag
    analyze_only = "--analyze-only" in sys.argv or "-n" in sys.argv
    
    # Find Ghidra
    ghidra_path = find_ghidra_installation()
    if not ghidra_path:
        print("ERROR: Could not find Ghidra installation")
        print("Please set GHIDRA_INSTALL_DIR environment variable or install to standard location")
        return 1
    
    print(f"Found Ghidra: {ghidra_path}")
    
    # TODO: Update these with your actual project location
    # You can find this in Ghidra: File -> Recent Projects
    project_path = r"C:\Users\benam\Documents\GhidraProjects"
    project_name = "D2Common"  # Or whatever your project is called
    
    # Check if project exists
    project_dir = os.path.join(project_path, f"{project_name}.rep")
    if not os.path.exists(project_dir):
        print(f"ERROR: Project not found at {project_dir}")
        print()
        print("Please update project_path and project_name in this script")
        print("You can find your project location in Ghidra: File -> Recent Projects")
        return 1
    
    # Run the fix
    return run_headless_fix(ghidra_path, project_path, project_name, analyze_only)

if __name__ == "__main__":
    sys.exit(main())
