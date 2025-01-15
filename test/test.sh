set -x

echo "Testing sm3 /sm4, sync & async"
echo "Testing hw, hw+ce, ce"
echo "Testing hw, hw+sve, sve"

default_size=8192
values=(1 2 4 8 16 32)

if [ -n "$1" ]; then
	size=$1
else
	size=$default_size
fi

for x in "${values[@]}"
do
	echo $x
	#sm4 sync
	numactl --cpubind=0 --membind=0 uadk_tool benchmark --alg sm4-128-ecb --mode sva --opt 0 --sync --pktlen $size --seconds 10 --multi 1 --thread $x --ctxnum $x --init2 --prefetch

	#sm4 async
	numactl --cpubind=0 --membind=0 uadk_tool benchmark --alg sm4-128-ecb --mode sva --opt 0 --async --pktlen $size --seconds 10 --multi 1 --thread $x --ctxnum $x --init2 --prefetch


	#sm3 sync
	numactl --cpubind=0 --membind=0 uadk_tool benchmark --alg sm3 --mode sva --opt 0 --sync --pktlen $size --seconds 20 --multi 1 --thread $x --ctxnum $x --init2 --prefetch

	#sm3 async
	numactl --cpubind=0 --membind=0 uadk_tool benchmark --alg sm3 --mode sva --opt 0 --async --pktlen $size --seconds 20 --multi 1 --thread $x --ctxnum $x --init2 --prefetch
done
