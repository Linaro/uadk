#!/bin/sh
if [ $1 == "clean" ]
then
    rm -f *.so
else
    gcc ../sched_sample.c -fPIC -I ../../include -I ../../ -shared -o libsched_test.so
    gcc test_sched.c -L -lsched_test -o test_sched
fi
