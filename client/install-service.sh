#!/bin/bash

# Run as a regular user: ./install-service.sh

set -e

echo -e "Installing RAMEN Client as a systemd service\n"

if sudo systemctl is-active --quiet ramen-client.service 2>/dev/null; then
    echo -e "The ramen-client service is currently running."
    echo -e "Stopping the service for the update..."
    sudo systemctl stop ramen-client.service
    SERVICE_WAS_RUNNING=1
else
    SERVICE_WAS_RUNNING=0
fi

if sudo systemctl list-unit-files 2>/dev/null | grep -q ramen-client.service; then
    echo -e "Service already installed. Updating..."
    SERVICE_EXISTS=1
else
    echo -e "New service installation."
    SERVICE_EXISTS=0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$SCRIPT_DIR/target/release/client" ]; then
    echo -e "Binary not found. Building..."
    cd "$SCRIPT_DIR"
    cargo build --release
    if [ $? -ne 0 ]; then
        echo -e "Build failed"
        exit 1
    fi
fi

echo -e "Creating directories..."
sudo mkdir -p /opt/ramen
sudo mkdir -p /etc/ramen
sudo mkdir -p /var/log/ramen

echo -e "Copying the binary to /usr/local/bin..."
sudo cp "$SCRIPT_DIR/target/release/client" /usr/local/bin/ramen-client
sudo chmod +x /usr/local/bin/ramen-client

# Copy the configuration file (always overwrite with the new one)
if [ -f "$SCRIPT_DIR/config.yaml" ]; then
    if sudo test -f "/etc/ramen/config.yaml"; then
        echo -e "Replacing the existing configuration file with the new one..."
    else
        echo -e "Copying the configuration file to /etc/ramen..."
    fi
    sudo cp "$SCRIPT_DIR/config.yaml" /etc/ramen/
else
    echo -e "Configuration file not found. Creating a template..."
    sudo tee /etc/ramen/config.yaml > /dev/null << 'EOF'
# RAMEN Client configuration
interface: eth0
check_interval_seconds: 300

servers:
  - name: "Server 1"
    server_ip: "192.168.1.100"
    http_port: 8000
    endpoint: "/api/config"
    service_port: 51820
    duration_seconds: 3600
EOF
    echo -e "WARNING: a template configuration file was created."
    echo -e "Edit /etc/ramen/config.yaml before starting the service!"
fi

sudo chmod 600 /etc/ramen/config.yaml
sudo chown root:root /etc/ramen/config.yaml

echo -e "Installing the systemd service..."
sudo cp "$SCRIPT_DIR/ramen-client.service" /etc/systemd/system/

echo -e "Reloading systemd..."
sudo systemctl daemon-reload
if [ $SERVICE_EXISTS -eq 0 ]; then
    echo -e "Enabling the service at boot..."
    sudo systemctl enable ramen-client.service
else
    echo -e "Service already enabled."
fi

if [ $SERVICE_WAS_RUNNING -eq 1 ]; then
    echo -e "Restarting the service..."
    sudo systemctl start ramen-client.service
    echo -e "Service restarted successfully!"
fi

echo -e "\nInstallation/update completed!\n"
echo -e "Useful commands:"
echo -e "  sudo systemctl start ramen-client     - Start the service"
echo -e "  sudo systemctl stop ramen-client      - Stop the service"
echo -e "  sudo systemctl restart ramen-client   - Restart the service"
echo -e "  sudo systemctl status ramen-client    - Service status"
echo -e "  sudo journalctl -u ramen-client -f    - Follow the logs in real time"
echo -e "  sudo systemctl disable ramen-client   - Disable start at boot"
echo -e ""
if [ $SERVICE_WAS_RUNNING -eq 0 ]; then
    echo -e "To start the service now: sudo systemctl start ramen-client"
fi
