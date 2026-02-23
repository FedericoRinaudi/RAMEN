#!/bin/bash

# Script to disable network offload features (GRO, GSO, TSO, etc.)
# These features interfere with eBPF packet processing

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

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run with sudo: sudo ./disable-offloads.sh"
    exit 1
fi

# Check if ethtool is installed
if ! command -v ethtool >/dev/null 2>&1; then
    log_error "ethtool not found. Installing..."
    apt-get update && apt-get install -y ethtool
fi

# Function to disable offloads on an interface
disable_offloads() {
    local iface=$1
    
    log_info "Disabling offloads on $iface..."
    
    #todo: attivo receive hashing
    ethtool -K "$iface" scatter-gather off    tcp-segmentation-offload off    generic-segmentation-offload off    generic-receive-offload off    rx-checksumming off    tx-checksumming off
    ethtool -K "$iface"  receive-hashing off    rx-vlan-filter off    tx-gre-segmentation off    tx-gre-csum-segmentation off    receive-hashing off   highdma off    tx-gre-segmentation off
    ethtool -K "$iface"  tx-gre-csum-segmentation off    tx-gso-partial off    macsec-hw-offload off
    
    log_success "Offloads disabled on $iface"
    
    # Show current status
    log_info "Current offload status for $iface:"
    ethtool -k "$iface" | grep -E "generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload|large-receive-offload|rx-checksumming|tx-checksumming|scatter-gather" || true
}

# If interface specified as argument, use it
if [ $# -gt 0 ]; then
    for iface in "$@"; do
        if ip link show "$iface" >/dev/null 2>&1; then
            disable_offloads "$iface"
        else
            log_error "Interface $iface not found"
        fi
    done
else
    # Auto-detect active network interfaces (excluding loopback and virtual)
    log_info "Auto-detecting network interfaces..."
    
    for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | grep -v '^docker' | grep -v '^veth' | grep -v '^br-'); do
        # Check if interface is up
        if ip link show "$iface" | grep -q "state UP"; then
            disable_offloads "$iface"
        else
            log_info "Skipping $iface (not up)"
        fi
    done
fi

log_success "Offload configuration complete!"
log_warning "Note: These settings are temporary and will reset on reboot."
log_info "To make permanent, add this script to your system startup."
