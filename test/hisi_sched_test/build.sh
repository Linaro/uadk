#!/bin/sh
gcc ../sched_sample.c test_sched.c -I ../../ -I ../../include/ -L -lsched -o test_sched -lpthread
