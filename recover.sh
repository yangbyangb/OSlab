#!/bin/sh

echo "ready to recover"
rmmod hello
lsmod | grep hello
cd /home/oslab/OSlab/virus
rm -f full-nelson
make clean
echo "successfully recovered"
