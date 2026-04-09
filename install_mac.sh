#!/usr/bin/env bash
# =============================================================================
# FATCA Crypto Utility — macOS Installer
#
# This script installs FATCACrypto on macOS:
#   1. Copies the executable to ~/Applications/FATCACrypto/
#   2. Creates a .command launcher on the Desktop
#   3. Makes it double-clickable from Finder
#
# Usage: bash install_mac.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="FATCA Crypto"
EXE_NAME="FATCACrypto"
INSTALL_DIR="$HOME/Applications/FATCACrypto"
DESKTOP="$HOME/Desktop"

echo "================================================"
echo "  FATCA Crypto Utility — Installation macOS"
echo "================================================"
echo ""

# Check if executable exists
if [ ! -f "$SCRIPT_DIR/dist/$EXE_NAME" ]; then
    echo "❌ Executable introuvable: dist/$EXE_NAME"
    echo "   Veuillez d'abord builder l'application avec:"
    echo "     bash build_executable.sh --gui"
    exit 1
fi

# Create install directory
echo "🔹 [1/3] Création du dossier d'installation..."
mkdir -p "$INSTALL_DIR"

# Copy executable
echo "🔹 [2/3] Copie de l'application..."
cp -f "$SCRIPT_DIR/dist/$EXE_NAME" "$INSTALL_DIR/$EXE_NAME"
chmod +x "$INSTALL_DIR/$EXE_NAME"

# Create a .command file on the Desktop (double-clickable in Finder)
echo "🔹 [3/3] Création du raccourci sur le Bureau..."
LAUNCHER="$DESKTOP/$APP_NAME.command"
cat > "$LAUNCHER" << 'LAUNCHER_SCRIPT'
#!/usr/bin/env bash
# FATCA Crypto — Desktop Launcher
"$HOME/Applications/FATCACrypto/FATCACrypto" &
exit 0
LAUNCHER_SCRIPT
chmod +x "$LAUNCHER"

echo ""
echo "================================================"
echo "  ✅ Installation terminée avec succès!"
echo "================================================"
echo ""
echo "  📂 Application installée dans: $INSTALL_DIR"
echo "  🖥  Raccourci créé sur le Bureau: $LAUNCHER"
echo ""
echo "  Double-cliquez sur \"$APP_NAME\" sur votre Bureau"
echo "  pour lancer l'application."
echo ""
