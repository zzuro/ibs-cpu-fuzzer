CBITPOS=51
RPB=1

qemu-system-x86_64 \
  -enable-kvm \
  -nographic \
  -machine q35 -smp 1 -m 2G \
  -cpu EPYC-v4 \
  -machine memory-encryption=sev0,vmport=off \
  -object memory-backend-memfd,id=ram1,size=2G,share=true,prealloc=false \
  -machine memory-backend=ram1 \
  -object sev-snp-guest,id=sev0,cbitpos=${CBITPOS},reduced-phys-bits=${RPB},kernel-hashes=off,policy=0x30000 \
  -bios /home/avezzu/edk2/Build/OvmfX64/RELEASE_GCC5/FV/OVMF.fd \
  -kernel /home/avezzu/ibs-cpu-fuzzer-dev/vms/guest/guest/arch/x86/boot/bzImage \
  -append "console=ttyS0 earlyprintk=serial loglevel=8" \
  -device virtio-serial