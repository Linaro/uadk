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

#VALGRIND=valgrind

have_hisi_zip=0
have_hisi_sec=0
have_hisi_hpre=0
zip_result=-1
sec_result=-1
hpre_result=-1

RM="rm"
CP="cp"
CHMOD="chmod"

SUCCESS_COUNT=0
FAIL_COUNT=0

# arg1: zip/sec/hpre
# Return UACCE mode. Return -1 if UACCE module is invalid.
check_uacce_mode()
{
	case $1 in
	"zip")
		if [ ! -f "/sys/module/hisi_zip/parameters/uacce_mode" ]; then
			mode=-1
		else
			mode=`cat /sys/module/hisi_zip/parameters/uacce_mode`
		fi
		;;
	"sec")
		if [ ! -f "/sys/module/hisi_sec2/parameters/uacce_mode" ]; then
			mode=-1
		else
			mode=`cat /sys/module/hisi_sec2/parameters/uacce_mode`
		fi
		;;
	"hpre")
		if [ ! -f "/sys/module/hisi_hpre/parameters/uacce_mode" ]; then
			mode=-1
		else
			mode=`cat /sys/module/hisi_hpre/parameters/uacce_mode`
		fi
		;;
	*)
		mode=-1
		;;
	esac
	return $mode
}

run_cmd()
{
	local exit_code=0
	local output=""
	# The first parameter is always comment. So remove it.
	local comment="$1"
	shift
	echo "Command: $@"

	if [ -z ${VALGRIND} ]; then
		# "|| exit_code=$?" is used to capature the return value.
		# It could prevent bash to stop scripts when error occurs.
		output=$("$@" 2>&1) || exit_code=$?
	else
		output=$("${VALGRIND} $@" 2>&1)
	fi
	echo "$output"
	if [ $exit_code -eq 0 ]; then
		((SUCCESS_COUNT++))
		echo -e "\tCommand passed (CMD: $comment)."
	else
		((FAIL_COUNT++))
		echo -e "\tCommand failed (CMD: $comment)."
		echo -e "\tCommand result: $exit_code"
	fi
	return $exit_code
}

run_cmd_quiet()
{
	local exit_code=0
	local output=""
	# The first parameter is always comment. So remove it.
	local comment="$1"
	shift
	echo "Command: $@"

	if [ -z ${VALGRIND} ]; then
		# "|| exit_code=$?" is used to capature the return value.
		# It could prevent bash to stop scripts when error occurs.
		output=$("$@" 2>&1) || exit_code=$?
	else
		output=$("${VALGRIND} $@" 2>&1)
	fi
	if [ $exit_code -eq 0 ]; then
		((SUCCESS_COUNT++))
		echo -e "\tCommand passed (CMD: $comment)."
	else
		((FAIL_COUNT++))
		echo "$output"
		echo -e "\tCommand failed (CMD: $comment)."
		echo -e "\tCommand result: $exit_code"
	fi
	return $exit_code
}

show_file_size()
{
	echo -e "\tsrc [$1]: $(stat -c %s $1)"
	echo -e "\tdst [$2]: $(stat -c %s $2)"
}

run_zip_test_v1()
{
	dd if=/dev/urandom of=origin bs=512K count=1 >& /dev/null
	run_cmd "HW compress 512K file for zlib format" test_hisi_zip -z < origin > hw.zlib

	dd if=/dev/urandom of=origin bs=512K count=1 >& /dev/null
	run_cmd "HW compress 512K file for gzip format" test_hisi_zip -g < origin > hw.gz
}

# arg1: source file, arg2: destination file, arg3: algorithm type
hw_blk_deflate()
{
	case $3 in
	"gzip")
		${RM} -f /tmp/gzip_list.bin
		run_cmd "HW compress for gzip format in block mode" \
			uadk_tool test --m zip --alg 2 --in $1 --out $2 ${@:4}
		show_file_size $1 $2
		;;
	"zlib")
		run_cmd "HW compress for zlib format in block mode" \
			uadk_tool test --m zip --alg 1 --in $1 --out $2 ${@:4}
		show_file_size $1 $2
		;;
	*)
		echo "Unsupported algorithm type: $3"
		return -1
		;;
	esac
}

# arg1: source file, arg2: destination file, arg3: algorithm type
hw_blk_inflate()
{
	case $3 in
	"gzip")
		run_cmd "HW decompress for gzip format in block mode" \
			uadk_tool test --m zip --alg 2 --inf --in $1 --out $2 ${@:4}
		show_file_size $1 $2
		;;
	"zlib")
		run_cmd "HW decompress for zlib format in block mode" \
			uadk_tool test --m zip --alg 1 --inf --in $1 --out $2 ${@:4}
		show_file_size $1 $2
		;;
	*)
		echo "Unsupported algorithm type: $3"
		return -1
		;;
	esac
}

# arg1: source file, arg2: destination file, arg3: algorithm type
hw_strm_deflate()
{
	case $3 in
	"gzip")
		run_cmd "HW compress for gzip format in stream mode" \
			uadk_tool test --m zip --stream --alg 2 --in $1 --out $2 ${@:4}
		show_file_size $1 $2
		;;
	"zlib")
		run_cmd "HW compress for zlib format in stream mode" \
			uadk_tool test --m zip --stream --alg 1 --in $1 --out $2 ${@:4}
		show_file_size $1 $2
		;;
	*)
		echo "Unsupported algorithm type: $3"
		return -1
		;;
	esac
}

# arg1: source file, arg2: destination file, arg3: algorithm type
hw_strm_inflate()
{
	case $3 in
	"gzip")
		run_cmd "HW decompress for gzip format in stream mode" \
			uadk_tool test --m zip --stream --alg 2 --inf --in $1 --out $2 ${@:4}
		show_file_size $1 $2
		;;
	"zlib")
		run_cmd "HW decompress for zlib format in stream mode" \
			uadk_tool test --m zip --stream --alg 1 --inf --in $1 --out $2 ${@:4}
		show_file_size $1 $2
		;;
	*)
		echo "Unsupported algorithm type: $3"
		return -1
		;;
	esac
}

# arg1: source file, arg2: destination file, arg3: algorithm type
sw_strm_deflate()
{
	case $3 in
	"gzip")
		gzip -c --fast < $1 > $2 || exit_code=$?
		echo "SW stream compress"
		show_file_size $1 $2
		;;
	*)
		echo "Unsupported algorithm type: $3"
		return -1
		;;
	esac
}

# arg1: source file, arg2: destination file, arg3: algorithm type
sw_strm_inflate()
{
	case $3 in
	"gzip")
		gunzip < $1 > $2 || exit_code=$?
		echo "SW stream decompress"
		show_file_size $1 $2
		;;
	*)
		echo "Unsupported algorithm type: $3"
		return -1
		;;
	esac
}

# arg1: random, arg2: indicates X MB of random file
# arg1: existed file name
prepare_src_file()
{
	case $1 in
	"random")
		dd if=/dev/urandom of=origin bs=1M count=$2 &> /dev/null
		;;
	*)
		${CP} $1 origin
		${CHMOD} 777 origin
		;;
	esac
}

# arg1: existed text file
hw_dfl_sw_ifl()
{
	${RM} -f origin /tmp/ori.gz ori.md5
	echo "hardware compress with gzip format and software decompress:"
	# Generate random data with 1MB size
	echo "with 1MB random data"
	prepare_src_file random 1
	md5sum origin > ori.md5

	${RM} -f /tmp/ori.gz
	hw_strm_deflate origin /tmp/ori.gz gzip --env
	sw_strm_inflate /tmp/ori.gz origin gzip
	run_cmd "Check MD5 after HW stream compress & SW decompress on 1MB random data" \
		md5sum -c ori.md5

	# Generate random data with 500MB size
	echo "with 500MB random data"
	prepare_src_file random 500
	md5sum origin > ori.md5

	${RM} -f /tmp/ori.gz
	hw_strm_deflate origin /tmp/ori.gz gzip --env
	sw_strm_inflate /tmp/ori.gz origin gzip
	run_cmd "Check MD5 after HW stream compress & SW decompress on 500MB random data" \
		md5sum -c ori.md5

	# Use existed text file. It's not in alignment.
	echo "with text file $1"
	${RM} -f origin /tmp/ori.gz ori.md5
	prepare_src_file $1
	md5sum origin > ori.md5

	# This case fails.
	${RM} -f /tmp/ori.gz
	hw_strm_deflate origin /tmp/ori.gz gzip --env
	sw_strm_inflate /tmp/ori.gz origin gzip
	run_cmd "Check MD5 after HW stream compress & SW decompress on text data" \
		md5sum -c ori.md5
}

# arg1: existed text file
sw_dfl_hw_ifl()
{
	${RM} -f origin /tmp/ori.gz ori.md5
	echo "gzip compress and hardware decompress:"
	# Generate random data with 1MB size
	echo "with 1MB random data"
	prepare_src_file random 1
	md5sum origin > ori.md5

	sw_strm_deflate origin /tmp/ori.gz gzip 8192
	hw_strm_inflate /tmp/ori.gz origin gzip --env
	run_cmd "Check MD5 after SW compress & HW stream decompress on 1MB random data" \
		md5sum -c ori.md5

	# Generate random data with 500MB size
	echo "with 500MB random data"
	prepare_src_file random 500
	md5sum origin > ori.md5

	${RM} -f /tmp/ori.gz
	sw_strm_deflate origin /tmp/ori.gz gzip 8192
	hw_strm_inflate /tmp/ori.gz origin gzip --env
	run_cmd "Check MD5 after SW compress & HW stream decompress on 500MB random data" \
		md5sum -c ori.md5

	# Use existed text file. It's not in alignment.
	echo "with text file $1"
	${RM} -f origin /tmp/ori.gz ori.md5
	prepare_src_file $1
	md5sum origin > ori.md5

	sw_strm_deflate origin /tmp/ori.gz gzip 8192
	hw_strm_inflate /tmp/ori.gz origin gzip --env
	run_cmd "Check MD5 after SW compress & HW stream decompress on text data" \
		md5sum -c ori.md5
}

# arg1: existed text file
hw_dfl_hw_ifl()
{
	${RM} -f origin /tmp/ori.gz ori.md5
	echo "hardware compress and hardware decompress:"
	# Generate random data with 1MB size
	echo "with 1MB random data"
	prepare_src_file random 1
	md5sum origin > ori.md5

	hw_blk_deflate origin /tmp/ori.gz gzip
	hw_blk_inflate /tmp/ori.gz origin gzip
	run_cmd_quiet "Check MD5 after HW block compress & HW block decompress on 1MB random data" \
		md5sum -c ori.md5

	${RM} -f /tmp/ori.gz
	hw_strm_deflate origin /tmp/ori.gz gzip
	hw_strm_inflate /tmp/ori.gz origin gzip
	run_cmd_quiet "Check MD5 after HW stream compress & HW stream decompress on 1MB random data" \
		md5sum -c ori.md5

	# Use existed text file. It's not in alignment.
	echo "with text file $1"
	${RM} -f origin /tmp/ori.gz ori.md5
	prepare_src_file $1
	md5sum origin > ori.md5

	hw_blk_deflate origin /tmp/ori.gz gzip
	hw_blk_inflate /tmp/ori.gz origin gzip
	run_cmd_quiet "Check MD5 after HW block compress & HW block decompress on text data" \
		md5sum -c ori.md5

	${RM} -f /tmp/ori.gz
	hw_strm_deflate origin /tmp/ori.gz gzip
	hw_strm_inflate /tmp/ori.gz origin gzip
	run_cmd_quiet "Check MD5 after HW stream compress & HW stream decompress on text data" \
		md5sum -c ori.md5
}

# failed: return 1; success: return 0
run_zip_test_v2()
{
	export WD_COMP_CTX_NUM="sync-comp:4@0,sync-decomp:4@0,async-comp:4@0,async-decomp:4@0"
	export WD_COMP_ASYNC_POLL_EN=1
	export WD_COMP_ASYNC_POLL_NUM="4@0"
	# test without environment variables
	# limit test text file in 8MB
	rm -fr /tmp/textfile
	dd if=/dev/urandom bs=1M count=8 | tr -dc '[:print:]\n' | head -c 8M > /tmp/textfile
	sw_dfl_hw_ifl /tmp/textfile
	hw_dfl_sw_ifl /tmp/textfile
	WD_COMP_EPOLL_EN=1 hw_dfl_hw_ifl /tmp/textfile
	WD_COMP_EPOLL_EN=0 hw_dfl_hw_ifl /tmp/textfile
	# test without environment variables
	#run_cmd "compress performance test without environment variables" \
	#	uadk_tool test --m zip --stream --blksize 8192 --size 81920 --loop 1000 --self
	# test with environment variables
	#run_cmd "compress performance test with environment variables" \
	#	uadk_tool test --m zip --stream --blksize 8192 --size 81920 --loop 1000 --self --env
}

# Accept more paraterms
# failed: return 1; success: return 0
run_sec_test_v2()
{
	run_cmd "sec test in sync mode" \
		uadk_tool test --m sec --cipher 0 --optype 0 --pktlen 16 --keylen 16 \
		--times 1 --sync --multi 1 $@

	run_cmd "sec test in async mode" \
		uadk_tool test --m sec --cipher 0 --optype 0 --pktlen 16 --keylen 16 \
		--times 1 --async --multi 1 $@

	run_cmd "digest test in sync mode" \
		uadk_tool test --m sec --digest 0 --optype 0 --pktlen 16 --keylen 16 \
		--times 1 --sync --multi 1 $@

	run_cmd "digest test in async mode" \
		uadk_tool test --m sec test_hisi_sec --digest 0 --optype 0 --pktlen 16 --keylen 16 \
		--times 1 --async --multi 1 $@
}

# failed: return 1; success: return 0
run_hpre_test_v2()
{
	dev_path=$(ls -1 /dev/hisi_hpre-* | head -1)
	run_cmd "hpre test in sync mode" \
		test_hisi_hpre --trd_mode=sync --dev_path=$dev_path

	run_cmd "hpre test in async mode" \
		test_hisi_hpre --trd_mode=async --dev_path=$dev_path
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

	echo "Passed ${SUCCESS_COUNT} test. Failed ${FAIL_COUNT} test."
	if [ ${FAIL_COUNT} -ne 0 ]; then
		return 1
	fi

	return 0
}

# start to test
find /dev -name hisi_zip-* &> /dev/null
if [ $? -eq 0 ]; then
	chmod 666 /dev/hisi_zip-*
	have_hisi_zip=1
	check_uacce_mode zip || exit_code=$?
	if [ $exit_code -eq 1 ]; then
		run_zip_test_v2
		zip_result=$?
	else
		run_zip_test_v1
		zip_result=$?
	fi
fi

find /dev -name hisi_sec2-* &> /dev/null
if [ $? -eq 0 ]; then
	chmod 666 /dev/hisi_sec2-*
	have_hisi_sec=1
	check_uacce_mode sec || exit_code=$?
	if [ $exit_code -eq 1 ]; then
		# Run without sglnum parameter
		run_sec_test_v2
		sec_result=$?
		# Re-run with sglnum parameter
		run_sec_test_v2 --sglnum=2
		sec_result=$?
	else
		# Skip to test sec temporarily
		sec_result=0
	fi
fi

find /dev -name hisi_hpre-* &> /dev/null
if [ $? -eq 0 ]; then
	chmod 666 /dev/hisi_hpre-*
	have_hisi_hpre=1
	check_uacce_mode hpre || exit_code=$?
	if [ $exit_code -eq 1 ]; then
		run_hpre_test_v2
		hpre_result=$?
	else
		# Skip to test sec temporarily
		hpre_result=0
	fi
fi

output_result
