#!/bin/sh

echo "ready to insmod"
cd /home/oslab/OSlab/virus/
make
insmod hello.ko
lsmod | grep hello
echo "done with the module"
