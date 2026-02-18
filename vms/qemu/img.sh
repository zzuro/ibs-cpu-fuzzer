#!/usr/bin/env bash

set -e

IMAGE_NAME="ubuntu-24.04-server-cloudimg-amd64.img"
RAW_NAME="ubuntu-24.04-server-cloudimg-amd64.raw"
URL="https://cloud-images.ubuntu.com/releases/24.04/release/${IMAGE_NAME}"

echo "Downloading Ubuntu 24.04 cloud image..."
curl -LO "$URL"

echo "Converting qcow2 image to raw format..."
qemu-img convert -f qcow2 -O raw "$IMAGE_NAME" "$RAW_NAME"

echo "Done!"
echo "Raw image created: $RAW_NAME"
