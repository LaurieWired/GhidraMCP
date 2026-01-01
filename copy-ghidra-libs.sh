#!/bin/zsh

# Copy Ghidra JAR files to project lib directory
echo "Copying Ghidra JAR files to project lib directory..."

# Create lib directory if it doesn't exist
mkdir -p lib

# Set source directory - use parameter if provided, otherwise use default
if [ -z "$1" ]; then
    # Try to auto-detect Ghidra location
    if [ -d "/opt/homebrew/Cellar/ghidra" ]; then
        # Homebrew installation - find the latest version
        GHIDRA_VERSION=$(ls /opt/homebrew/Cellar/ghidra | sort -V | tail -1)
        GHIDRA_DIR="/opt/homebrew/Cellar/ghidra/$GHIDRA_VERSION/libexec"
    elif [ -d "/Applications/Ghidra" ]; then
        GHIDRA_DIR="/Applications/Ghidra"
    else
        echo "Error: Could not find Ghidra installation."
        echo "Usage: $0 /path/to/ghidra"
        exit 1
    fi
    echo "Using auto-detected Ghidra directory: $GHIDRA_DIR"
else
    GHIDRA_DIR="$1"
    # Handle Homebrew Cellar path - check if libexec exists
    if [ -d "$GHIDRA_DIR/libexec/Ghidra" ]; then
        GHIDRA_DIR="$GHIDRA_DIR/libexec"
    elif [ -d "$GHIDRA_DIR/Ghidra" ]; then
        : # Standard installation, use as-is
    else
        # Try to find the version directory for Homebrew
        if [ -d "$GHIDRA_DIR" ]; then
            SUBDIR=$(ls "$GHIDRA_DIR" 2>/dev/null | head -1)
            if [ -d "$GHIDRA_DIR/$SUBDIR/libexec/Ghidra" ]; then
                GHIDRA_DIR="$GHIDRA_DIR/$SUBDIR/libexec"
            fi
        fi
    fi
    echo "Using provided Ghidra directory: $GHIDRA_DIR"
fi

# Verify the directory structure exists
if [ ! -d "$GHIDRA_DIR/Ghidra" ]; then
    echo "Error: Invalid Ghidra directory - $GHIDRA_DIR/Ghidra does not exist"
    exit 1
fi

# Copy JAR files
echo "Copying Base.jar..."
cp "$GHIDRA_DIR/Ghidra/Features/Base/lib/Base.jar" lib/

echo "Copying Decompiler.jar..."
cp "$GHIDRA_DIR/Ghidra/Features/Decompiler/lib/Decompiler.jar" lib/

echo "Copying Docking.jar..."
cp "$GHIDRA_DIR/Ghidra/Framework/Docking/lib/Docking.jar" lib/

echo "Copying Generic.jar..."
cp "$GHIDRA_DIR/Ghidra/Framework/Generic/lib/Generic.jar" lib/

echo "Copying Project.jar..."
cp "$GHIDRA_DIR/Ghidra/Framework/Project/lib/Project.jar" lib/

echo "Copying SoftwareModeling.jar..."
cp "$GHIDRA_DIR/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar" lib/

echo "Copying Utility.jar..."
cp "$GHIDRA_DIR/Ghidra/Framework/Utility/lib/Utility.jar" lib/

echo "Copying Gui.jar..."
cp "$GHIDRA_DIR/Ghidra/Framework/Gui/lib/Gui.jar" lib/

echo ""
echo "All Ghidra JAR files have been copied successfully!"
echo ""
