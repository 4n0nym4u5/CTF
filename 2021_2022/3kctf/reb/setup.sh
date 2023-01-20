#!/bin/bash
echo "[+] Installing Intel PIN"
URL=https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.18-98332-gaebd7b1e6-gcc-linux.tar.gz

wget $URL -O pin.tar.gz 
tar -xvf pin.tar.gz
rm pin.tar.gz
#Install Ubuntu Dependencies
sudo apt-get install gcc-multilib g++-multilib libc6-dev-i386
#Rename pin directory
mv pin-* pin