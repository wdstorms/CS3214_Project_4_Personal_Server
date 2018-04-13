#!/bin/bash

#
# Run this script to install the required Jansson and JWT packages.
#
BASE=`pwd`
test -d ${BASE}/deps || mkdir ${BASE}/deps
git clone git@github.com:akheron/jansson.git
(cd jansson;
    autoreconf -fi;
    ./configure --prefix=${BASE}/deps;
    make install
)

git clone git@github.com:benmcollins/libjwt.git
(cd libjwt;
    autoreconf -fi;
    env PKG_CONFIG_PATH=../deps/lib/pkgconfig:${PKG_CONFIG_PATH} ./configure --prefix=${BASE}/deps;
    make install
)
