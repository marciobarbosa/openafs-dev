#!/bin/sh

make clean

./regen

ARCHFLAGS="-arch x86_64" ./configure --enable-transarc-paths --with-krb5-conf=/usr/bin/krb5-config --enable-debug-kernel

ARCHFLAGS="-arch x86_64" make dest
