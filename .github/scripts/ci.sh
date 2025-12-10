#!/bin/bash
set -e

echo "=== CI start ==="
echo "USER: $(whoami)"
echo "DIR $(pwd)"

WORKSPACE="$(pwd)"
BUILD_DIR="$(pwd)/deps"
LOCK_FILE="/var/lock/uadk-lock"

lock() {
    exit_code=1
    pending=0
    while [ "$exit_code" != 0 ]; do
        exit_code=0
        sudo mkdir ${LOCK_FILE} &> /dev/null || exit_code=$?
        if [ "$exit_code" != 0 ]; then
            if [ "$pending" = 0 ]; then
                # Some script is accessing hardware
                echo "Wait for other building script finishing."
                pending=1
            fi
        fi
    done
}

unlock() {
    if [ -d ${LOCK_FILE} ]; then
        sudo rmdir ${LOCK_FILE}
        echo "Release lock"
    fi
}

trap 'unlock' EXIT

clean_previous_installations() {
    sudo rm -f /usr/local/lib/libwd*
    sudo rm -rf /usr/local/lib/uadk/
}

detect_repository() {
    local current_repo=$(git config --get remote.origin.url)
    if [[ "$current_repo" == *"uadk" ]]; then
        echo "UADK_PR"
    elif [[ "$current_repo" == *"uadk_engine" ]]; then
        echo "UADK_ENGINE_PR"
    else
        echo "UNKNOWN"
    fi
}

lock || exit 1
clean_previous_installations

REPO_TYPE=$(detect_repository)
echo "repo: $REPO_TYPE"

mkdir -p "$BUILD_DIR"

sudo chmod 666 /dev/hisi_* 2>/dev/null || {
    echo "no hisi hardware, only compile"
    ONLY_COMPILE=1
}

build_uadk() {
    ./cleanup.sh
    ./autogen.sh
    if [ -n "$1" ]; then
        ./configure --enable-static --disable-shared --with-static_drv
    else
        ./configure
    fi

    make -j$(nproc)
    sudo make install

    if [ -n "$ONLY_COMPILE" ]; then
	    exit 0
    fi

    sudo ./test/sanity_test.sh
}

build_uadk_engine() {
    version=$(openssl version)
    major_version=$(echo $version | awk -F'[ .]' '{print $2}')
    echo "OpenSSL major version is "$major_version

    if (( major_version >= 3 )); then
        dir="/usr/lib64/ossl-modules/"
    else
        dir="/usr/local/lib/engines-1.1/"
    fi

    autoreconf -i
    ./configure --libdir="$dir" CFLAGS=-Wall
    make -j$(nproc)
    sudo make install

    if [ -n "$ONLY_COMPILE" ]; then
	    exit 0
    fi

    ./test/sanity_test.sh
}

case "$REPO_TYPE" in
    "UADK_PR")
        echo "=== CI UADK PR ==="
	build_uadk --static
	build_uadk

	# verify uadk_engine
	cd "$BUILD_DIR"
	git clone --depth 1 https://github.com/Linaro/uadk_engine.git
	cd uadk_engine
	build_uadk_engine
	;;

    "UADK_ENGINE_PR")
	echo "=== ci UADK Engine PR ==="

	# install dependent uadk
	cd "$BUILD_DIR"
	git clone --depth 1 https://github.com/Linaro/uadk.git
	cd uadk
	build_uadk

        # build current uadk_engine pr
	cd "$WORKSPACE"
	build_uadk_engine
	;;
	esac

	echo "🎉 CI  succeed: $REPO_TYPE"
