CBITPOS=51
RPB=1

# Only create login.img if it does not exist
if [ ! -f qemu/login.img ]; then
  echo "Creating login.img..."
  cloud-localds qemu/login.img qemu/user-data.yaml
else
  echo "login.img already exists. Skipping cloud-localds."
fi

qemu-system-x86_64 \
  -enable-kvm \
  -nographic \
  -machine q35 -smp 6 -m 6G \
  -drive "if=virtio,format=qcow2,file=qemu/ubuntu-24.04-server-cloudimg-amd64.img" \
  -drive if=virtio,format=raw,file=qemu/login.img \
  -net nic,model=e1000 -net user,hostfwd=tcp::2222-:22 \
  -cpu EPYC-v4 \
  -machine memory-encryption=sev0,vmport=off \
  -object memory-backend-memfd,id=ram1,size=6G,share=true,prealloc=false \
  -machine memory-backend=ram1 \
  -object sev-snp-guest,id=sev0,cbitpos=${CBITPOS},reduced-phys-bits=${RPB},kernel-hashes=off,policy=0x30000 \
  -bios /usr/share/ovmf/OVMF.amdsev.fd