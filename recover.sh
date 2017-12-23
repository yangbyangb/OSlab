#!/bin/sh

echo "ready to recover"
rmmod hello
lsmod | grep hello
cd /home/oslab/OSlab/virus
rm -f full-nelson
rm -f *.o *.ko *.mod.c *.symvers *.order
echo "successfully recovered"
