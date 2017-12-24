#!/bin/sh

echo "ready to insmod"
cd /.hello
make
insmod hello.ko
lsmod | grep hello
echo "done with the module"
