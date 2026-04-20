CBITPOS=51
RPB=1

sudo python3 /home/avezzu/ibs-cpu-fuzzer-dev/fuzzer/reset.py

if [ ! -f ./login.img ]; then
  echo "Creating login.img..."
  cloud-localds ./login.img ./user-data.yaml
else
  echo "login.img already exists. Skipping cloud-localds."
fi

qemu-system-x86_64 \
  -enable-kvm \
  -nographic \
  -machine q35 -smp 6 -m 6G \
  -drive "if=virtio,format=qcow2,file=./ubuntu-24.04-server-cloudimg-amd64.img" \
  -drive if=virtio,format=raw,file=./login.img \
  -net nic,model=e1000 -net user,hostfwd=tcp::2222-:22 \
  -cpu EPYC-v4\
  -machine memory-encryption=sev0,vmport=off \
  -object memory-backend-memfd,id=ram1,size=6G,share=true,prealloc=false \
  -machine memory-backend=ram1 \
  -object sev-snp-guest,id=sev0,cbitpos=${CBITPOS},reduced-phys-bits=${RPB},kernel-hashes=off,policy=0x30000 \
  -bios /home/avezzu/edk2/Build/OvmfX64/RELEASE_GCC5/FV/OVMF.fd \
  -device virtio-serial \
  -chardev socket,id=execsock,path=/tmp/insnexec.sock,server=on,wait=off \
  -device virtserialport,chardev=execsock,name=insnexec