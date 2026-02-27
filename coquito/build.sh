cd bootloader
make mrproper
make

cd ../coquito
make clean
make

cd ..
./.venv/bin/python image_build.py -b ./bootloader/vector.bin -c ./coquito/coquito.elf ../vms/qemu/min_kernel_ovmf.fddeactivate