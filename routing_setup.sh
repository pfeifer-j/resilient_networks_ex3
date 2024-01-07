#!/bin/bash

# Install apt deps
sudo apt-get update && sudo apt-get install -y python3 python3-pip git make gcc autoconf zlib1g-dev libbz2-dev

# Build and install bgpdump from source
git clone -b v1.6.2 https://github.com/RIPE-NCC/bgpdump /tmp/bgpdump
cd /tmp/bgpdump
sh ./bootstrap.sh
make
./bgpdump -T
sudo cp /tmp/bgpdump/bgpdump /usr/local/bin/

# Install python wrapper
pip3 install --user bgpdumpy

