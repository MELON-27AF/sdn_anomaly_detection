#!/bin/bash
# Script untuk menyiapkan lingkungan SDN controller

# Warna untuk output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Setting up SDN Controller Environment ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo)${NC}"
  exit 1
fi

# Update system
echo -e "${YELLOW}Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
apt-get install -y \
    python3 \
    python3-pip \
    git \
    mininet \
    openvswitch-switch \
    net-tools \
    iputils-ping \
    tcpdump \
    hping3 \
    nmap \
    wget \
    curl

# Upgrade pip
pip3 install --upgrade pip

# Install Python packages
echo -e "${YELLOW}Installing Python packages...${NC}"
pip3 install ryu numpy requests

# Check if Ryu installed correctly
if python3 -c "import ryu" 2>/dev/null; then
echo -e "${GREEN}Ryu successfully installed${NC}"
else
    echo -e "${RED}Failed to install Ryu. Please install manually:${NC}"
    echo "pip3 install ryu"
    exit 1
fi

# Create log directory
echo -e "${YELLOW}Creating log directory...${NC}"
mkdir -p ~/sdn_anomaly_detection/logs

# Check if Mininet is installed correctly
if which mn > /dev/null; then
    echo -e "${GREEN}Mininet is installed${NC}"
else
    echo -e "${RED}Mininet not found. Please install manually:${NC}"
    echo "apt-get install mininet"
    exit 1
fi

# Test OVS installation
if which ovs-vsctl > /dev/null; then
    echo -e "${GREEN}Open vSwitch is installed${NC}"
else
    echo -e "${RED}Open vSwitch not found. Please install manually:${NC}"
    echo "apt-get install openvswitch-switch"
    exit 1
fi

# Cleanup any existing Mininet instances
echo -e "${YELLOW}Cleaning up Mininet...${NC}"
mn -c

echo -e "${GREEN}Controller setup completed successfully!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Make sure the edge node is set up with the model"
echo "2. Update the controller IP in anomaly_detection_controller.py"
echo "3. Run 'ryu-manager anomaly_detection_controller.py'"
echo "4. In another terminal, run 'sudo python3 sdn_topology.py'"
echo ""
