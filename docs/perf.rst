
App: test_bind_api
The test app generate pseudo-random number for test so no input file required.
Output will be double checked with inflate, which is ignored if "-o perf"

para:
-o perf: ignore output check, for better performance
	 non-sva mode simulate memcpy output buffer
-c: number of caches to run together, for batch processing.


1. sva mode
sudo rmmod hisi_zip; sudo rmmod hisi_qm; sudo rmmod uacce;
sudo insmod uacce.ko; sudo insmod hisi_qm.ko; sudo insmod hisi_zip.ko;

Conslusion:
a. Add memset (hack in the code) to trigger page fault early in cpu instead of in the smmu
   Can improve performance a lot

   //no memset
   $ sudo ./test/test_bind_api -b 8192 -s 81920000 -o perf -c 50
   Compress bz=8192, speed=1942.876 MB/s

   //add memset
   $ sudo ./test/test_bind_api -b 8192 -s 81920000 -o perf -c 50
   Compress bz=8192, speed=7002.958 MB/s

b. multi-package -c can improve performance a lot, best performance for 60 packages.
Hardware can ensure sequence output for multi package in single queue

$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf
Compress bz=8192, speed=556.533 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 10
Compress bz=8192, speed=1381.276 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 20
Compress bz=8192, speed=3134.403 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 30
Compress bz=8192, speed=4316.537 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 40
Compress bz=8192, speed=5617.674 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 50
Compress bz=8192, speed=6715.231 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 60
Compress bz=8192, speed=7245.201 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 70
Compress bz=8192, speed=7271.500 MB/s

c. -q, multi-queue has no impact to performance
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 10 -q 10
Compress bz=8192, speed=1413.388 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 20 -q 10
Compress bz=8192, speed=3054.980 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 30 -q 10
Compress bz=8192, speed=4405.628 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 40 -q 10
Compress bz=8192, speed=5611.219 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 50 -q 10
Compress bz=8192, speed=6560.715 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 60 -q 10
Compress bz=8192, speed=6812.435 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 70 -q 10
Compress bz=8192, speed=6774.040 MB/s


2. nosva:
sudo rmmod hisi_zip; sudo rmmod hisi_qm; sudo rmmod uacce;
sudo insmod uacce.ko uacce_nosva=1; sudo insmod hisi_qm.ko; sudo insmod hisi_zip.ko;
sudo ./test_bind_api -b 8192 -s 81920000 -o perf
Compress bz=8192, speed=2203.808 MB/s

Conclusion:
a, Already add memcpy when -o perf to simulate real case
If no memcpy, speed = 5G/s
b, memset, -c, -q has no impact to performance

$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf
Compress bz=8192, speed=2294.555 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 10
Compress bz=8192, speed=2274.646 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 10 -q 10
Compress bz=8192, speed=2253.909 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 20
Compress bz=8192, speed=2252.999 MB/s
$ sudo ./test_bind_api -b 8192 -s 81920000 -o perf -c 20 -q 10
Compress bz=8192, speed=2244.004 MB/s

3. test.sh

#!/bin/bash

block=8192
size=81920000

for i in {1..10}
do
	let "size*=$i"
	echo $i $size
	sudo ./test_bind_api -b $block -s $size -o perf -c 50
done

Conslusion:
a. only support 5w packages at most, since no enough memory for malloc
b. sva mode:
When pacakge larger than 4w, performance downgrade from 6G to 300M since page fault happen
The reason may caused by migration, known issue

log:
./test.sh
1 81920000
Compress bz=8192, speed=7033.219 MB/s
2 163840000
Compress bz=8192, speed=6593.940 MB/s
3 491520000
Compress bz=8192, speed=6595.981 MB/s
4 1966080000
Compress bz=8192, speed=324.536 MB/s
5 9830400000
Compress bz=8192, speed=532.281 MB/s
6 58982400000
7 412876800000
8 3303014400000
9 29727129600000
10 297271296000000
