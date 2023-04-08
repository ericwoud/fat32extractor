#!/bin/bash

dd if=/dev/zero of=./fat32test.img bs=16M count=4
mkfs.fat -v -F 32 -S 512 -s 4 ./fat32test.img
mkdir -p ./imagefiles/longlongtestdir/testdir
echo "test" > ./imagefiles/testfile
echo "another test" > ./imagefiles/longlongtestdir/file.txt
dd if=/dev/urandom of=./imagefiles/longlongtestdir/Image bs=18M count=1
mcopy -soi ./fat32test.img ./imagefiles/* ::
mdir -/ -i ./fat32test.img
make
./fat32extractor ./fat32test.img
./fat32extractor ./fat32test.img /longlongtestdir/Image ./Image.out
diff -s ./imagefiles/longlongtestdir/Image ./Image.out
rm -rf ./imagefiles
rm ./Image.out

