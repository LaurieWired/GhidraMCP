@echo off
setlocal

:: Copy Ghidra JAR files to project lib directory
echo Copying Ghidra JAR files to project lib directory...

:: Create lib directory if it doesn't exist
if not exist "lib" mkdir lib

:: Set source directory - use parameter if provided, otherwise use default
if "%~1"=="" (
    set GHIDRA_DIR=F:\ghidra_11.4.2
    echo Using default Ghidra directory: !GHIDRA_DIR!
) else (
    set GHIDRA_DIR=%~1
    echo Using provided Ghidra directory: !GHIDRA_DIR!
)

:: Enable delayed expansion for variables
setlocal enabledelayedexpansion

:: Copy JAR files
echo Copying Base.jar...
copy "%GHIDRA_DIR%\Ghidra\Features\Base\lib\Base.jar" "lib\" /Y

echo Copying Decompiler.jar...
copy "%GHIDRA_DIR%\Ghidra\Features\Decompiler\lib\Decompiler.jar" "lib\" /Y

echo Copying Docking.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Docking\lib\Docking.jar" "lib\" /Y

echo Copying Generic.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Generic\lib\Generic.jar" "lib\" /Y

echo Copying Project.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Project\lib\Project.jar" "lib\" /Y

echo Copying SoftwareModeling.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\SoftwareModeling\lib\SoftwareModeling.jar" "lib\" /Y

echo Copying Utility.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Utility\lib\Utility.jar" "lib\" /Y

echo Copying Gui.jar...
copy "%GHIDRA_DIR%\Ghidra\Framework\Gui\lib\Gui.jar" "lib\" /Y

echo.
echo All Ghidra JAR files have been copied successfully!
echo.
