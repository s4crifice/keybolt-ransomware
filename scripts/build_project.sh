#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# Update system packages
echo -e "${BLUE}Updating package lists...${NC}"
sudo apt update && echo -e "${GREEN}Package list updated.${NC}" || echo -e "${RED}Failed to update package list.${NC}"

# Install mingw-w64
echo -e "${BLUE}Installing MinGW for cross-compilation...${NC}"
if sudo apt install -y mingw-w64; then
    echo -e "${GREEN}MinGW installed successfully.${NC}"
else
    echo -e "${RED}Failed to install MinGW.${NC}"
    exit 1
fi

# Create build directory
echo -e "${BLUE}Creating build directory...${NC}"
mkdir -p ../build && echo -e "${GREEN}Build directory created.${NC}" || echo -e "${RED}Failed to create build directory.${NC}"

# Compile the project
echo -e "${YELLOW}Compiling the project...${NC}"
if x86_64-w64-mingw32-gcc -o ../build/encrypt.exe ../src/main.c \
    -I../dependencies/openssl/include \
    -L../dependencies/openssl/lib64 \
    -L../lib \
    -static -lssl -lcrypto -lpthread -ladvapi32 -luser32 -lcrypt32 -lws2_32 -liphlpapi; then
    echo -e "${GREEN}Compilation succeeded. Executable created at ../build/encrypt.exe${NC}"
else
    echo -e "${RED}Compilation failed.${NC}"
    exit 1
fi

echo -e "${GREEN}Build script completed successfully.${NC}"
