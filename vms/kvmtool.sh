./kvmtool/lkvm run \
  --name ubuntu-24.04 \
  --disk qemu/ubuntu-24.04-server-cloudimg-amd64.raw \
  --disk qemu/login.img \
  --cpus 6 \
  --mem 6144 \
  --param "console=ttyS0 root=/dev/vda1" \
  --network mode=user \
  --kernel /home/avezzu/linux-6.17/arch/x86_64/boot/bzImage
