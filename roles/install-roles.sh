#!/bin/bash
# Created by @ZephrFish 
# https://zephrsec.com | https://blog.zsec.uk
# install-roles.sh - Register all custom roles with Ludus
#
# Usage:
#   First install:   ./install-roles.sh
#   Force update:    ./install-roles.sh --update
#
# --update / --force / -f  Force-reinstall ALL roles (community + custom).
#   Use this whenever you download a new version of the bundle to ensure
#   all roles are updated to the latest version. Without this flag, already-
#   installed roles are skipped even if the bundle contains newer versions.
#
# Installs all custom roles from this directory plus required community roles
# (badsectorlabs.*) from Ansible Galaxy.

set -e

# Parse flags
FORCE_FLAG=""
for arg in "$@"; do
    case "$arg" in
        --force|-f|--update|-u) FORCE_FLAG="--force" ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROLES_DIR="$SCRIPT_DIR"
LUDUS_BASE="${LUDUS_BASE:-/opt/ludus}"

# Check that expected role directories exist alongside this script
ROLE_DIRS=$(find "$ROLES_DIR" -maxdepth 1 -type d \( -name "mde_prereqs" -o -name "wef" -o -name "sysmon" \) 2>/dev/null | wc -l | tr -d ' ')
if [ "$ROLE_DIRS" -eq 0 ]; then
    echo "ERROR: No lab roles found in: $ROLES_DIR"
    echo ""
    echo "This script must be run from (or located in) the directory containing"
    echo "the role folders. Expected structure:"
    echo "  $ROLES_DIR/"
    echo "    install-roles.sh"
    echo "    mde_prereqs/"
    echo "    wef/"
    echo "    sysmon/"
    echo "    ..."
    echo ""
    echo "Current directory contents:"
    ls -d "$ROLES_DIR"/*/ 2>/dev/null | head -10 || echo "  (empty or no subdirectories)"
    exit 1
fi

echo "=== MDE/MDI Detection Lab - Role Installation ==="
echo ""

# Check if ludus command exists
if ! command -v ludus &>/dev/null; then
    echo "ERROR: 'ludus' command not found."
    echo "Are you running this on the Ludus host?"
    exit 1
fi

# Check LUDUS_API_KEY is set — without it, ludus cannot authenticate over SSH
# (the system keyring is unavailable in SSH sessions, so all role installs silently fail)
if [ -z "$LUDUS_API_KEY" ]; then
    echo "ERROR: LUDUS_API_KEY is not set."
    echo "Export your API key before running this script:"
    echo "  export LUDUS_API_KEY='<userid>.<your-key>'"
    exit 1
fi

# Validate key format and extract userid (expected: "<userid>.<key>")
LUDUS_USERID="${LUDUS_API_KEY%%.*}"
if [ -z "$LUDUS_USERID" ] || [ "$LUDUS_USERID" = "$LUDUS_API_KEY" ]; then
    echo "ERROR: LUDUS_API_KEY does not look right (expected format: '<userid>.<key>')."
    echo "  Got: $LUDUS_API_KEY"
    exit 1
fi
echo "Installing roles for Ludus user: $LUDUS_USERID"
echo ""

# ── Auto-detect existing installs ───────────────────────────────────────────
# If roles are already installed and --update wasn't passed, warn and offer to proceed.
# Resolve the server-side role directory. The API key userID (e.g. "pve1") may
# differ from the proxmox username used in the filesystem path (e.g. "pve01").
LUDUS_PROXMOX_USER=$(ludus user list --json 2>/dev/null | grep -o '"proxmoxUsername":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -n "$LUDUS_PROXMOX_USER" ]; then
    LUDUS_ROLES_DIR="${LUDUS_BASE}/users/${LUDUS_PROXMOX_USER}/.ansible/roles"
else
    LUDUS_ROLES_DIR="${LUDUS_BASE}/users/${LUDUS_USERID}/.ansible/roles"
fi

# Detect existing installations and auto-suggest --update if needed
EXISTING_ROLES=$(ls "${LUDUS_ROLES_DIR}"/mde_prereqs "${LUDUS_ROLES_DIR}"/wef "${LUDUS_ROLES_DIR}"/sysmon 2>/dev/null | wc -l | tr -d ' ')
if [ "$EXISTING_ROLES" -gt 0 ] && [ -z "$FORCE_FLAG" ]; then
    echo "============================================================"
    echo "  EXISTING INSTALLATION DETECTED"
    echo "============================================================"
    echo "  Found ${EXISTING_ROLES} roles already installed."
    echo ""
    echo "  Without --update, already-installed roles are SKIPPED"
    echo "  and will NOT receive bug fixes or new features."
    echo ""
    echo "  To update all roles to this version, re-run with:"
    echo "    ./install-roles.sh --update"
    echo ""
    echo "  Continuing with install-only mode (new roles only) ..."
    echo "============================================================"
    echo ""
fi

# Count all custom role directories (anything with a tasks/main.yml)
ROLE_COUNT=$(find "$ROLES_DIR" -maxdepth 2 -name "main.yml" -path "*/tasks/*" | wc -l | tr -d ' ')
echo "Found $ROLE_COUNT custom roles to install."
if [ -n "$FORCE_FLAG" ]; then
    echo "Mode: FORCE UPDATE — all roles will be reinstalled from this bundle."
fi
echo ""

# Install community roles
echo "--- Installing Community Roles ---"
for role in badsectorlabs.ludus_adcs; do
    echo "  Installing: $role"
    if ! ludus ansible role add $FORCE_FLAG "$role" 2>/dev/null; then
        echo "    (already installed or network unavailable — skipping)"
    fi
done
echo ""

# Install all custom roles found in this directory
echo "--- Installing Custom Roles ---"
INSTALLED=0
FAILED=0

for role_dir in "$ROLES_DIR"/*/; do
    [ -d "$role_dir" ] || continue
    role_name=$(basename "$role_dir")
    if [ -f "$role_dir/tasks/main.yml" ]; then
        echo "  Installing: $role_name"
        # Workaround: Ludus's --force can leave broken role dirs on the server.
        # When --force is set, remove the server-side copy first so the fresh
        # install always succeeds.
        if [ -n "$FORCE_FLAG" ] && [ -d "$LUDUS_ROLES_DIR/$role_name" ]; then
            rm -rf "$LUDUS_ROLES_DIR/$role_name"
        fi
        install_output=$(ludus ansible role add -d "$role_dir" 2>&1)
        install_exit=$?
        if echo "$install_output" | grep -q "NOT installed successfully\|error\|ERROR" 2>/dev/null || [ $install_exit -ne 0 ]; then
            echo "    WARNING: Failed to install $role_name"
            echo "    $install_output" | grep -i "error\|NOT installed" | head -3
            FAILED=$((FAILED + 1))
        else
            INSTALLED=$((INSTALLED + 1))
        fi
    else
        echo "  Skipping: $role_name (no tasks/main.yml)"
    fi
done

echo ""
echo "=== Installation Complete ==="
echo "  Installed: $INSTALLED"
echo "  Failed:    $FAILED"
echo "  Total:     $ROLE_COUNT"
echo ""
if [ "$FAILED" -gt 0 ]; then
    echo "  WARNING: $FAILED role(s) failed to install."
    echo "  Re-run with --update to retry, or check output above for details."
    echo ""
fi
echo "Verify roles are registered:"
echo "  ludus ansible role list | grep -E 'ad_population|adcs_lab|mde_prereqs|pivot_tools|preflight|rsat|smb_shares|sysmon|wef'  # should show $ROLE_COUNT+ entries"
echo ""
echo "Next steps (run from the project root, not from roles/):"
echo "  1. Set your config:  ludus range config set -f zsec-mde-mdi-lab.yml"
echo "  2. Deploy:           ludus range deploy"
echo ""
echo "Already deployed and just updating roles?"
echo "  ludus range deploy --tags user-defined-roles   # re-runs roles without VM rebuild"
