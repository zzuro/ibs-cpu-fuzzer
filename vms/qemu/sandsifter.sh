CBITPOS=51
RPB=1

if [ ! -f ./login.img ]; then
  echo "Creating login.img..."
  cloud-localds ./login.img ./user-data.yaml
else
  echo "login.img already exists. Skipping cloud-localds."
fi

qemu-system-x86_64 \
  -enable-kvm \
  -nographic \
  -machine q35,smm=off,confidential-guest-support=sev0 \
  -smp 1 -m 6G \
  -drive if=virtio,format=qcow2,file=./ubuntu-24.04-server-cloudimg-amd64.img \
  -drive if=virtio,format=raw,file=./login.img \
  -net nic,model=e1000 -net user,hostfwd=tcp::2222-:22 \
  -cpu EPYC-v4 \
  -object memory-backend-memfd,id=ram1,size=6G,share=true,prealloc=false \
  -machine memory-backend=ram1 \
  -object sev-guest,id=sev0,cbitpos=${CBITPOS},reduced-phys-bits=${RPB},policy=0x1 \
  -bios /usr/share/ovmf/OVMF.amdsev.fd \
  -device virtio-serial \
  -chardev socket,id=execsock,path=/tmp/insnexec.sock,server=on,wait=off \
  -device virtserialport,chardev=execsock,name=insnexec