#!/bin/bash -e
#
# This is a sanity test about uadk algorithms.
#
# Before test, please build uadk and install it into system according to the
# steps in INSTALL doc.
#
# Please feel free to add more basic tests.
#
# If user doesn't install the binaries, libraries and head files into the
# configed path, user must specify path in this way.
#
# $sudo LD_LIBRARY_PATH={library path} PATH={bin path}	\
# C_INCLUDE_PATH={head path} sanity_test.sh

#VALGRIND=valgrind

have_hisi_zip=0
have_hisi_sec=0
have_hisi_hpre=0
zip_result=-1
sec_result=-1
hpre_result=-1

run_cmd()
{
	exit_code=0
	if [ -z ${VALGRIND} ]; then
		$@ &> /dev/null || exit_code=$?
	else
		${VALGRIND} $@
	fi
	return $exit_code
}

# failed: return 1; success: return 0
run_zip_test()
{
	run_cmd zip_sva_perf -b 8192 -l 1000 -v -m 0

	run_cmd zip_sva_perf -b 8192 -l 1 -v -m 1

	dd if=/dev/urandom of=origin bs=1M count=1 &> /dev/null
	md5sum origin > ori.md5
	zip_sva_perf -F < origin > hw.gz
	zip_sva_perf -F -d < hw.gz > origin
	md5sum -c ori.md5

	dd if=/dev/urandom of=origin bs=1M count=1 &> /dev/null
	md5sum origin > ori.md5
	zip_sva_perf -F -z -t 64 < origin > hw.zlib
	zip_sva_perf -F -z -d -t 64 < hw.zlib > origin
	md5sum -c ori.md5

	dd if=/dev/urandom of=origin bs=1M count=1 &> /dev/null
	md5sum origin > ori.md5
	zip_sva_perf -F -m 1 < origin > hw.gz
	zip_sva_perf -F -d -m 1 < hw.gz > origin
	md5sum -c ori.md5 || exit_code=$?


	dd if=/dev/urandom of=origin bs=10M count=50 &> /dev/null
	md5sum origin > ori.md5
	zip_sva_perf -S -F < origin > hw.gz
	zip_sva_perf -S -F -d < hw.gz > origin
	md5sum -c ori.md5


	dd if=/dev/urandom of=origin bs=1M count=1 &> /dev/null
	md5sum origin > ori.md5
	zip_sva_perf -F < origin > hw.gz
	gunzip < hw.gz > origin
	md5sum -c ori.md5

	dd if=/dev/urandom of=origin bs=10M count=1 &> /dev/null
	md5sum origin > ori.md5
	zip_sva_perf -S -F < origin > hw.gz
	gunzip < hw.gz > origin
	md5sum -c ori.md5
}

# Accept more paraterms
# failed: return 1; success: return 0
run_sec_test()
{
	run_cmd test_hisi_sec --cipher 0 --optype 0 --pktlen 16 --keylen 16 \
		--times 1 --sync --multi 1 $@

	run_cmd test_hisi_sec --cipher 0 --optype 0 --pktlen 16 --keylen 16 \
		--times 1 --async --multi 1 $@

	run_cmd test_hisi_sec --digest 0 --optype 0 --pktlen 16 --keylen 16 \
		--times 1 --sync --multi 1 $@

	run_cmd test_hisi_sec --digest 0 --optype 0 --pktlen 16 --keylen 16 \
		--times 1 --async --multi 1 $@
}

# failed: return 1; success: return 0
run_hpre_test()
{
	run_cmd test_hisi_hpre --trd_mode=sync

	run_cmd test_hisi_hpre --trd_mode=async
}

# failed: return 1; success: return 0
output_result()
{
	echo "test result:"
	if [ $have_hisi_zip -eq 0 ]; then
		echo "---> hisi_zip device is not existed!"
	fi

	if [ $have_hisi_sec -eq 0 ]; then
		echo "---> hisi_sec device is not existed!"
	fi

	if [ $have_hisi_hpre -eq 0 ]; then
		echo "---> hisi_hpre device is not existed!"
	fi

	if [ $zip_result == 1 ]; then
		echo "---> hisi_zip test is failed!"
	fi

	if [ $sec_result == 1 ]; then
		echo "---> hisi_sec test is failed!"
	fi

	if [ $hpre_result == 1 ]; then
		echo "---> hisi_hpre test is failed!"
	fi

	if [ $zip_result -ne 1 -a $sec_result -ne 1 -a $hpre_result -ne 1 ]; then
		echo "===> tests for exited device are all passed!"
		return 0
	fi

	return 1
}

# start to test
find /dev -name hisi_zip-* &> /dev/null
if [ $? -eq 0 ]; then
	chmod 666 /dev/hisi_zip-*
	have_hisi_zip=1
	run_zip_test
	zip_result=$?
fi

find /dev -name hisi_sec2-* &> /dev/null
if [ $? -eq 0 ]; then
	chmod 666 /dev/hisi_sec2-*
	have_hisi_sec=1
	# Run without sglnum parameter
	run_sec_test
	sec_result=$?
	# Re-run with sglnum parameter
	run_sec_test --sglnum=2
	sec_result=$?
fi

find /dev -name hisi_hpre-* &> /dev/null
if [ $? -eq 0 ]; then
	chmod 666 /dev/hisi_hpre-*
	have_hisi_hpre=1
	run_hpre_test
	hpre_result=$?
fi

output_result
