qemu-system-x86_64 \
  -enable-kvm \
  -nographic \
  -machine q35 -smp 1 -m 6G \
  -cpu host \
  -net none \
  -serial mon:stdio \
  -bios /home/avezzu/ibs-cpu-fuzzer/vms/qemu/min_kernel_ovmf.fd 
