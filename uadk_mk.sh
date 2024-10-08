#!/bin/bash

make clean

./autogen.sh

./conf.sh --static

make -j8
