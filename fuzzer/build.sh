#!/usr/bin/env bash

set -euo pipefail

echo "Cleaning old build artifacts..."
rm -f *.deb *.buildinfo *.changes

echo "Building kernel..."
cd linux

make -j"$(getconf _NPROCESSORS_ONLN)"
make bindeb-pkg -j"$(nproc)" LOCALVERSION=-ibs

cd ..

echo "Installing packages..."
sudo dpkg -i ./*.deb

echo "Updating grub..."
sudo update-grub

echo "Done."