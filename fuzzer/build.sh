rm *.deb
rm *.buildinfo
rm *.changes


cd linux
make -j `getconf _NPROCESSORS_ONLN` 
make bindeb-pkg -j$(nproc) LOCALVERSION=-ibs
cd ..

sudo dpkg -i *.deb

sudo update-grub