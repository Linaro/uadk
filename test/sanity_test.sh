#!/bin/bash
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

have_hisi_zip=0
have_hisi_sec=0
have_hisi_hpre=0
zip_result=-1
sec_result=-1
hpre_result=-1

TEST_FILE=test_uadk_lib.c

# wd_get_acce_list() is available in v2. Use this function to test
# whether libwd.so is v2.
cat << EOF > ${TEST_FILE}
#include <stdio.h>
#include <uadk/wd.h>

int main(void)
{
	wd_get_accel_list("zip");
	return 0;
}
EOF

# failed: return 1; success: return 0
check_uadk_lib()
{
	# check UADK v2
	exit_code=0
	if [ ! -z ${LD_LIBRARY_PATH} ]; then
		gcc -Wl,-v ${TEST_FILE} -L${LD_LIBRARY_PATH} -lwd || exit_code=$?
	else
		gcc -Wl,-v ${TEST_FILE} -lwd || exit_code=$?
	fi
	if [ $exit_code -ne 0 ]; then
		rm ${TEST_FILE}
		return 1
	fi
	rm ${TEST_FILE}
	return 0
}

# failed: return 1; success: return 0
run_zip_test()
{
	zip_sva_perf -b 8192 -l 1000 -v -m 0 &> /dev/null
	if [ $? -ne 0 ]; then
		return 1
	fi

	zip_sva_perf -b 8192 -l 1 -v -m 1 &> /dev/null
	if [ $? -ne 0 ]; then
		return 1
	fi

	return 0
}

# failed: return 1; success: return 0
run_sec_test()
{
	test_hisi_sec --cipher 0 --optype 0 --pktlen 16 --keylen 16 --times 1 \
		      --sync --multi 1 &> /dev/null
	if [ $? -ne 0 ]; then
		return 1
	fi

	test_hisi_sec --cipher 0 --optype 0 --pktlen 16 --keylen 16 --times 1 \
		      --async --multi 1 &> /dev/null
	if [ $? -ne 0 ]; then
		return 1
	fi

	test_hisi_sec --digest 0 --optype 0 --pktlen 16 --keylen 16 --times 1 \
		      --sync --multi 1 &> /dev/null
	if [ $? -ne 0 ]; then
		return 1
	fi

	test_hisi_sec --digest 0 --optype 0 --pktlen 16 --keylen 16 --times 1 \
		      --async --multi 1 &> /dev/null
	if [ $? -ne 0 ]; then
		return 1
	fi

	return 0
}

# failed: return 1; success: return 0
run_hpre_test()
{
	test_hisi_hpre --trd_mode=sync &> /dev/null
	if [ $? -ne 0 ]; then
		return 1
	fi

	test_hisi_hpre --trd_mode=async &> /dev/null
	if [ $? -ne 0 ]; then
		return 1
	fi

	return 0
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

check_uadk_lib
if [ $? -ne 0 ]; then
	# Abandon the test since v1 tests are not supported yet.
	# And it's not treated as an error.
	exit 0
fi

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
	run_sec_test
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
