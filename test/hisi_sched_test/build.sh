#!/bin/sh
if [ $1 == "clean" ]
then
    rm -f *.so
else
    gcc ../sched_sample.c -fPIC -I ../../include -I ../../ -shared -o libsched.so
    gcc test_sched.c -I ../../ -I ../../include/ -L -lsched -o test_sched -lpthread
fi
