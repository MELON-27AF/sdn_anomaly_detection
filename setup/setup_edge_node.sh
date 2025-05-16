#!/bin/bash
# Script untuk menyiapkan lingkungan Edge Node untuk inferensi model

# Warna untuk output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Setting up Edge Node Environment ===${NC}"

# Update system
echo -e "${YELLOW}Updating system packages...${NC}"
sudo apt-get update
sudo apt-get upgrade -y

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
sudo apt-get install -y \
    python3 \
    python3-pip \
    git \
    wget \
    curl

# Upgrade pip
pip3 install --upgrade pip

# Install Python packages
echo -e "${YELLOW}Installing Python packages...${NC}"
pip3 install tensorflow flask numpy

# Check if TensorFlow installed correctly
if python3 -c "import tensorflow" 2>/dev/null; then
    echo -e "${GREEN}TensorFlow successfully installed${NC}"
else
    echo -e "${RED}Failed to install TensorFlow. Please install manually:${NC}"
    echo "pip3 install tensorflow"
    exit 1
fi

# Check if Flask installed correctly
if python3 -c "import flask" 2>/dev/null; then
    echo -e "${GREEN}Flask successfully installed${NC}"
else
    echo -e "${RED}Failed to install Flask. Please install manually:${NC}"
    echo "pip3 install flask"
    exit 1
fi

# Create necessary directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p ~/sdn_anomaly_detection/edge_node/models
mkdir -p ~/sdn_anomaly_detection/logs

# Check if TFLite model exists
MODEL_PATH="~/sdn_anomaly_detection/edge_node/models/cnn_lstm_cicids2017_colab.tflite"
if [ -f "$MODEL_PATH" ]; then
    echo -e "${GREEN}TFLite model found at $MODEL_PATH${NC}"
else
    echo -e "${YELLOW}TFLite model not found at $MODEL_PATH${NC}"
    echo -e "${YELLOW}Please copy your model to this location before running the edge service${NC}"
fi

# Configure firewall to allow Flask port
echo -e "${YELLOW}Configuring firewall to allow port 5000...${NC}"
sudo ufw allow 5000/tcp || true

echo -e "${GREEN}Edge node setup completed successfully!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Make sure your TFLite model is in ~/sdn_anomaly_detection/edge_node/models/"
echo "2. Run 'python3 ~/sdn_anomaly_detection/edge_node/edge_inference_service.py'"
echo "3. Test the service with: curl http://localhost:5000/health"
echo ""
