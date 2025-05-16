#!/bin/bash
# Common dependencies for both controller and edge node

# Warna untuk output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Installing Common Dependencies ===${NC}"

# Update package list
echo -e "${YELLOW}Updating package list...${NC}"
sudo apt-get update

# Install common packages
echo -e "${YELLOW}Installing common packages...${NC}"
sudo apt-get install -y \
    python3 \
    python3-pip \
    git \
    wget \
    curl \
    nano \
    htop

# Upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip3 install --upgrade pip

# Install common Python packages
echo -e "${YELLOW}Installing common Python packages...${NC}"
pip3 install \
    numpy \
    matplotlib \
    pandas \
    seaborn

echo -e "${GREEN}Common dependencies installed successfully!${NC}"
