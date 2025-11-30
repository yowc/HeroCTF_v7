#!/bin/bash

# ==============================================================================
#  Admin Git Review & Commit Script
# ==============================================================================
#
# DESCRIPTION:
# This script is intended to be run by an 'admin' user. It automates the
# process of reviewing and committing changes from a user-submitted Git
# repository archive.
#

# --- Configuration ---

# Path to the admin's "official" repository.
# This script will initialize it if it doesn't exist.
ADMIN_REPO_PATH="/app"
# Directory to temporarily extract user submissions.
TEMP_DIR="/home/peter/git-review-$$" # $$ ensures a unique directory per run


# --- Script Body ---

# Exit immediately if a command exits with a non-zero status.
set -e

# Function to print messages with a prefix
log() {
    echo "[ADMIN GIT COMMIT] $1"
}


# 1. Validate user input
if [ "$#" -ne 1 ]; then
    log "ERROR: You must provide the path to one repository archive (.tar.gz)."
    log "Usage: $0 <path-to-archive.tar.gz>"
    exit 1
fi

USER_ARCHIVE=$1

if [ ! -f "$USER_ARCHIVE" ]; then
    log "ERROR: File not found: $USER_ARCHIVE"
    exit 1
fi


# 2. Prepare for review
log "Received submission: $USER_ARCHIVE"
mkdir -p "$TEMP_DIR"
log "Extracting archive to temporary directory: $TEMP_DIR"
tar -xzf "$USER_ARCHIVE" -C "$TEMP_DIR"

EXTRACTED_DIR=$(find "$TEMP_DIR" -mindepth 1 -maxdepth 1 -type d)
cd "$EXTRACTED_DIR"
log "Changed directory to $(pwd)"


# 3.1 Security Check 1: Verify commit history
log "Verifying that your repository is up-to-date..."
ADMIN_LAST_COMMIT=$(git --git-dir="$ADMIN_REPO_PATH/.git" log -1 --pretty=%H)
USER_LAST_COMMIT=$(git log -1 --pretty=%H)

log "Admin's latest commit: $ADMIN_LAST_COMMIT"
log "Your latest commit:    $USER_LAST_COMMIT"

if [ "$ADMIN_LAST_COMMIT" != "$USER_LAST_COMMIT" ]; then
    log "REJECTED: Your repository's last commit does not match the official repository."
    log "Please pull the latest changes from the official repository before submitting."
    rm -rf "$TEMP_DIR"
    exit 1
fi

log "SUCCESS: Commit history matches."


# 3.2 Security Check 2: Verify .git/config integrity
log "Verifying integrity of .git/config file..."
ADMIN_CONFIG_HASH=$(sha256sum "$ADMIN_REPO_PATH/.git/config" | awk '{ print $1 }')
USER_CONFIG_HASH=$(sha256sum ".git/config" | awk '{ print $1 }')

log "Admin's .git/config hash: $ADMIN_CONFIG_HASH"
log "Your .git/config hash:    $USER_CONFIG_HASH"

if [ "$ADMIN_CONFIG_HASH" != "$USER_CONFIG_HASH" ]; then
    log "REJECTED: Your .git/config file has been tampered with. Integrity check failed."
    rm -rf "$TEMP_DIR"
    exit 1
fi

log "SUCCESS: .git/config is valid. Proceeding with review."


# 4. Review and Commit the changes
log "Reviewing your proposed changes..."
echo "--------------------------------------------------"
git status
echo "--------------------------------------------------"

log "Everything looks good. Adding your changes to the staging area."
git add .

log "Committing your changes to the official branch. Stand by..."
GIT_COMMITTER_NAME="Admin" GIT_COMMITTER_EMAIL="admin@localhost" \
git commit -m "Accepted user submission" > /dev/null

log "Changes successfully committed."


# 5. Cleanup
log "Cleaning up temporary files..."
cd /
rm -rf "$TEMP_DIR"

log "Process complete. Thank you for your contribution."
exit 0
