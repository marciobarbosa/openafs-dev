#!/bin/sh

make clean

./regen

ARCHFLAGS="-arch i386 -arch x86_64" ./configure --enable-transarc-paths --with-krb5-conf=/usr/bin/krb5-config

ARCHFLAGS="-arch i386 -arch x86_64" make dest
