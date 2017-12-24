#!/bin/sh

echo "ready to insmod"
cd .
make
insmod hello.ko
lsmod | grep hello
echo "done with the module"
