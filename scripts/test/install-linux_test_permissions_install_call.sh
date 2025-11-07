#!/bin/bash

export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

TEST_TEMP_DIR=""

setUp() {
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
    INSTALL_DIR="$TEST_TEMP_DIR/install"
    BINARY_NAME="opkssh"
    mkdir -p "$INSTALL_DIR"
    HOME_POLICY=true
}

tearDown() {
    /usr/bin/rm -rf "$TEST_TEMP_DIR"
}

# Mock helper functions to keep main() progressing to the permissions call
ensure_command() { return 0; }
ensure_opkssh_user_and_group() { return 0; }
ensure_openssh_server() { return 0; }
check_selinux() { return 0; }
configure_opkssh() { return 0; }
configure_openssh_server() { return 0; }
restart_openssh_server() { return 0; }
configure_sudo() { return 0; }
log_opkssh_installation() { echo "log called" >> "$MOCK_LOG"; return 0; }

# Simulate installation by creating a wrapper binary that logs invocations
install_opkssh_binary() {
    cat > "$INSTALL_DIR/$BINARY_NAME" <<'EOF'
#!/bin/bash
echo "invoked: $*" >> "$MOCK_LOG"
EOF
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    return 0
}

test_installer_invokes_permissions_install() {
    # Run main; it should call the installed binary with 'permissions install'
    main
    result=$?
    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected main to succeed" 0 "$result"

    # Find any invocation lines and ensure permissions install was called
    found=0
    for l in "${mock_log[@]}"; do
        if [[ "$l" == invoked:*permissions*install* ]]; then
            found=1
            break
        fi
    done

    assertEquals "Expected installer to invoke 'permissions install' on the installed binary" 1 "$found"
}

# shellcheck disable=SC1091
source shunit2
