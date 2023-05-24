#!/bin/bash

PREFIX=/usr/local
rm -rf $PREFIX/include/kms_message
rm -rf $PREFIX/lib/cmake/kms_message
rm -rf $PREFIX/lib/pkgconfig/libkms_message.pc
rm -rf $PREFIX/lib/libkms_message.*
rm -rf $PREFIX/lib/cmake/mongocrypt
rm -rf $PREFIX/lib/pkgconfig/libmongocrypt*
rm -rf $PREFIX/include/mongocrypt
rm -rf $PREFIX/lib/libmongocrypt*
