#!/bin/bash

# Script to disable network offload features (GRO, GSO, TSO, etc.)
# These features interfere with eBPF packet processing

set -e

log_info() { echo -e "[INFO] $1"; }
log_success() { echo -e "[SUCCESS] $1"; }
log_warning() { echo -e "[WARNING] $1"; }
log_error() { echo -e "[ERROR] $1"; }

if [ "$EUID" -ne 0 ]; then
    log_error "Please run with sudo: sudo ./disable-offloads.sh"
    exit 1
fi

if ! command -v ethtool >/dev/null 2>&1; then
    log_error "ethtool not found. Installing..."
    apt-get update && apt-get install -y ethtool
fi

disable_offloads() {
    local iface=$1
    
    log_info "Disabling offloads on $iface..."
    
    #todo: enable receive hashing
    ethtool -K "$iface" scatter-gather off    tcp-segmentation-offload off    generic-segmentation-offload off    generic-receive-offload off    rx-checksumming off    tx-checksumming off
    ethtool -K "$iface"  receive-hashing off    rx-vlan-filter off    tx-gre-segmentation off    tx-gre-csum-segmentation off    receive-hashing off   highdma off    tx-gre-segmentation off
    ethtool -K "$iface"  tx-gre-csum-segmentation off    tx-gso-partial off    macsec-hw-offload off
    
    log_success "Offloads disabled on $iface"
    
    log_info "Current offload status for $iface:"
    ethtool -k "$iface" | grep -E "generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload|large-receive-offload|rx-checksumming|tx-checksumming|scatter-gather" || true
}

if [ $# -gt 0 ]; then
    for iface in "$@"; do
        if ip link show "$iface" >/dev/null 2>&1; then
            disable_offloads "$iface"
        else
            log_error "Interface $iface not found"
        fi
    done
else
    log_info "Auto-detecting network interfaces..."
    
    for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | grep -v '^docker' | grep -v '^veth' | grep -v '^br-'); do
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
