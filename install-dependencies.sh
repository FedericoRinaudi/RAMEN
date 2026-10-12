#!/bin/bash

# WFSafe - Complete Dependency Installation Script
# Installs all dependencies for eBPF, Rust, and the entire project

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if Ubuntu/Debian
if ! grep -qiE 'ubuntu|debian' /etc/os-release; then
    log_error "This script is designed for Ubuntu/Debian systems only"
    exit 1
fi

# Check sudo
if [ "$EUID" -ne 0 ]; then
    log_error "Please run with sudo: sudo ./install-dependencies.sh"
    exit 1
fi

# Get the actual user (not root)
ACTUAL_USER="${SUDO_USER:-$USER}"
ACTUAL_HOME=$(getent passwd "$ACTUAL_USER" | cut -d: -f6)

log_info "Installing eBPF dependencies for Ubuntu..."

# Update package list
log_info "Updating package list..."
apt-get update

# Essential build tools
log_info "Installing build essentials..."
apt-get install -y \
    build-essential \
    gcc \
    make \
    pkg-config \
    curl \
    git \
    wget \
    ca-certificates

# eBPF specific dependencies
log_info "Installing eBPF dependencies..."
apt-get install -y \
    clang-15 \
    llvm-15 \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev

# Kernel headers
log_info "Installing kernel headers..."
apt-get install -y linux-headers-$(uname -r)

# BPF tools - try to install what's available
log_info "Installing BPF tools..."
apt-get install -y bpfcc-tools 2>/dev/null || log_warning "bpfcc-tools not available"

# Try to install linux-tools, fallback if specific version not found
log_info "Installing linux-tools and bpftool..."
if ! apt-get install -y linux-tools-$(uname -r) 2>/dev/null; then
    log_warning "Specific linux-tools version not found, trying generic..."
    apt-get install -y linux-tools-generic || log_warning "linux-tools installation failed"
fi

# Additional attempt to ensure bpftool is available
if ! command -v bpftool >/dev/null; then
    log_info "Installing additional BPF tools..."
    apt-get install -y linux-tools-common
fi

# Additional dependencies for Rust and Rocket
log_info "Installing additional development dependencies..."
apt-get install -y \
    libssl-dev \
    openssl \
    netcat-openbsd

# Install Rust for the actual user (not root)
log_info "Installing Rust via rustup for user: $ACTUAL_USER..."
if ! command -v rustc >/dev/null 2>&1 || [ ! -f "$ACTUAL_HOME/.cargo/bin/rustc" ]; then
    log_info "Downloading and installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    log_success "Rust installed successfully"
else
    log_success "Rust is already installed"
fi

# Configure cargo environment immediately
log_info "Configuring cargo environment..."
. "$ACTUAL_HOME/.cargo/env"

# Export PATH for cargo in this script
export PATH="$ACTUAL_HOME/.cargo/bin:$PATH"
export CARGO_HOME="$ACTUAL_HOME/.cargo"
export RUSTUP_HOME="$ACTUAL_HOME/.rustup"

# Ensure Rust is up to date
log_info "Updating Rust toolchain..."
rustup update stable

# Install additional Rust components that might be needed
log_info "Installing additional Rust components..."
rustup component add clippy rustfmt

# Verify Rust installation
if rustc --version >/dev/null 2>&1; then
    RUST_VERSION=$(rustc --version)
    log_success "Rust toolchain ready: $RUST_VERSION"
else
    log_error "Rust installation verification failed"
    exit 1
fi

log_success "Dependencies installed successfully!"

# Verify clang-15
if command -v clang-15 >/dev/null; then
    log_success "clang-15 installed: $(clang-15 --version | head -1)"
else
    log_error "clang-15 not found!"
    exit 1
fi

# Verify and generate vmlinux.h
log_info "Setting up vmlinux.h generation..."

# Function to find and use bpftool
find_bpftool() {
    # Skip the wrapper in /usr/sbin/bpftool and find the real bpftool
    # Look for actual bpftool binaries in linux-tools directories
    local real_bpftool=$(find /usr/lib/linux-tools-* -name bpftool -type f -executable 2>/dev/null | head -1)
    
    if [ -n "$real_bpftool" ] && [ -x "$real_bpftool" ]; then
        echo "$real_bpftool"
        return 0
    fi
    
    # Fallback: try other standard locations (excluding the wrapper)
    for tool_path in /usr/bin/bpftool; do
        if [ -x "$tool_path" ]; then
            echo "$tool_path"
            return 0
        fi
    done
    
    return 1
}

# Generate vmlinux.h
generate_vmlinux() {
    local bpftool_path=$(find_bpftool)
    local script_dir="$(dirname "$0")"
    local ebpf_dir="$script_dir/eBPF/kernel"
    
    if [ -n "$bpftool_path" ]; then
        log_info "Found bpftool at: $bpftool_path"
        
        # Test if bpftool actually works (not just a wrapper)
        if ! sudo "$bpftool_path" version >/dev/null 2>&1; then
            log_warning "bpftool at $bpftool_path appears to be a non-functional wrapper"
            return 1
        fi
        
        # Check if eBPF directory exists
        if [ ! -d "$ebpf_dir" ]; then
            log_error "eBPF directory not found at: $ebpf_dir"
            return 1
        fi
        
        # Remove old vmlinux.h if exists
        rm -f "$ebpf_dir/vmlinux.h"
        
        # Try to generate vmlinux.h with better error handling
        log_info "Generating vmlinux.h from kernel BTF..."
        if sudo "$bpftool_path" btf dump file /sys/kernel/btf/vmlinux format c > "$ebpf_dir/vmlinux.h" 2>/tmp/bpftool_error.log; then
            if [ -s "$ebpf_dir/vmlinux.h" ]; then
                log_success "vmlinux.h generated successfully ($(du -h "$ebpf_dir/vmlinux.h" | cut -f1))"
                return 0
            else
                log_error "vmlinux.h was created but is empty"
                cat /tmp/bpftool_error.log 2>/dev/null || true
                return 1
            fi
        else
            log_error "Failed to generate vmlinux.h using $bpftool_path"
            log_info "Error details:"
            cat /tmp/bpftool_error.log 2>/dev/null || true
            return 1
        fi
    else
        log_error "bpftool not found in any standard location"
        return 1
    fi
}

if ! generate_vmlinux; then
    log_error "Could not generate vmlinux.h"
    exit 1
fi

# Test eBPF build
log_info "Testing eBPF build..."
cd "$(dirname "$0")/eBPF/kernel"

make clean 2>/dev/null || true

if make all; then
    log_success "eBPF build test successful!"
    make clean
else
    log_error "eBPF build test failed"
    exit 1
fi

log_success "============================================"
log_success "All dependencies installed successfully!"
log_success "============================================"
