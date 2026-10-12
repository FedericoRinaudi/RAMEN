#!/bin/bash

# Script per installare il RAMEN Client come servizio systemd
# Eseguire come utente normale: ./install-service.sh

set -e

# Colori per output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Installazione RAMEN Client come servizio systemd ===${NC}\n"

# Controlla se il servizio è già installato e in esecuzione
if sudo systemctl is-active --quiet RAMEN-client.service 2>/dev/null; then
    echo -e "${YELLOW}Il servizio RAMEN-client è attualmente in esecuzione.${NC}"
    echo -e "${YELLOW}Arresto del servizio per l'aggiornamento...${NC}"
    sudo systemctl stop RAMEN-client.service
    SERVICE_WAS_RUNNING=1
else
    SERVICE_WAS_RUNNING=0
fi

# Verifica se il servizio è già installato
if sudo systemctl list-unit-files 2>/dev/null | grep -q RAMEN-client.service; then
    echo -e "${YELLOW}Servizio già installato. Aggiornamento in corso...${NC}"
    SERVICE_EXISTS=1
else
    echo -e "${YELLOW}Nuova installazione del servizio.${NC}"
    SERVICE_EXISTS=0
fi

# Determina la directory dello script (dovrebbe essere la directory client)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verifica che il binario compilato esista
if [ ! -f "$SCRIPT_DIR/target/release/client" ]; then
    echo -e "${YELLOW}Il binario non è stato trovato. Compilazione in corso...${NC}"
    cd "$SCRIPT_DIR"
    cargo build --release
    if [ $? -ne 0 ]; then
        echo -e "${RED}Errore durante la compilazione${NC}"
        exit 1
    fi
fi

# Crea le directory necessarie
echo -e "${YELLOW}Creazione directory...${NC}"
sudo mkdir -p /opt/RAMEN
sudo mkdir -p /etc/RAMEN
sudo mkdir -p /var/log/RAMEN

# Copia il binario
echo -e "${YELLOW}Copia del binario in /usr/local/bin...${NC}"
sudo cp "$SCRIPT_DIR/target/release/client" /usr/local/bin/RAMEN-client
sudo chmod +x /usr/local/bin/RAMEN-client

# Copia il file di configurazione (sovrascrivi sempre con quello nuovo)
if [ -f "$SCRIPT_DIR/config.yaml" ]; then
    if sudo test -f "/etc/RAMEN/config.yaml"; then
        echo -e "${YELLOW}Sostituzione del file di configurazione esistente con quello nuovo...${NC}"
    else
        echo -e "${YELLOW}Copia del file di configurazione in /etc/RAMEN...${NC}"
    fi
    sudo cp "$SCRIPT_DIR/config.yaml" /etc/RAMEN/
else
    echo -e "${YELLOW}File di configurazione non trovato. Creazione di un template...${NC}"
    sudo tee /etc/RAMEN/config.yaml > /dev/null << 'EOF'
# Configurazione RAMEN Client
interface: eth0
check_interval_seconds: 300

servers:
  - name: "Server VPN 1"
    server_ip: "192.168.1.100"
    http_port: 8000
    endpoint: "/api/config"
    service_port: 51820
    duration_seconds: 3600
EOF
    echo -e "${RED}ATTENZIONE: È stato creato un file di configurazione template.${NC}"
    echo -e "${RED}Modificare /etc/RAMEN/config.yaml prima di avviare il servizio!${NC}"
fi

# Imposta i permessi corretti
sudo chmod 600 /etc/RAMEN/config.yaml
sudo chown root:root /etc/RAMEN/config.yaml

# Copia il file di servizio systemd
echo -e "${YELLOW}Installazione del servizio systemd...${NC}"
sudo cp "$SCRIPT_DIR/RAMEN-client.service" /etc/systemd/system/

# Ricarica systemd
echo -e "${YELLOW}Ricaricamento systemd...${NC}"
sudo systemctl daemon-reload
# Abilita il servizio all'avvio (se non era già abilitato)
if [ $SERVICE_EXISTS -eq 0 ]; then
    echo -e "${YELLOW}Abilitazione del servizio all'avvio...${NC}"
    sudo systemctl enable RAMEN-client.service
else
    echo -e "${YELLOW}Servizio già abilitato.${NC}"
fi

# Riavvia il servizio se era in esecuzione prima
if [ $SERVICE_WAS_RUNNING -eq 1 ]; then
    echo -e "${YELLOW}Riavvio del servizio...${NC}"
    sudo systemctl start RAMEN-client.service
    echo -e "${GREEN}✓ Servizio riavviato con successo!${NC}"
fi

echo -e "\n${GREEN}✓ Installazione/Aggiornamento completato!${NC}\n"
echo -e "Comandi utili:"
echo -e "  ${YELLOW}sudo systemctl start RAMEN-client${NC}     - Avvia il servizio"
echo -e "  ${YELLOW}sudo systemctl stop RAMEN-client${NC}      - Ferma il servizio"
echo -e "  ${YELLOW}sudo systemctl restart RAMEN-client${NC}   - Riavvia il servizio"
echo -e "  ${YELLOW}sudo systemctl status RAMEN-client${NC}    - Stato del servizio"
echo -e "  ${YELLOW}sudo journalctl -u RAMEN-client -f${NC}    - Visualizza i log in tempo reale"
echo -e "  ${YELLOW}sudo systemctl disable RAMEN-client${NC}   - Disabilita l'avvio automatico"
echo -e ""
if [ $SERVICE_WAS_RUNNING -eq 0 ]; then
    echo -e "${YELLOW}Per avviare il servizio ora:${NC} sudo systemctl start RAMEN-client"
fi
