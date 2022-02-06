#!/bin/bash

set -e

pushd $(dirname $0) > /dev/null
SCRIPTPATH=$(pwd)
popd > /dev/null
cd $SCRIPTPATH

SIGNIFY_REPO="https://github.com/aperezdc/signify"

MSG=$(mktemp -u msg.$$.XXXXXXXXXX)
PUB="${MSG}_key.pub"
PRIV="${MSG}_key.sec"

cleanup() {
  rm -f $PUB $PRIV $MSG $MSG.sig || true
}

cargo_run() {
  cargo run -q $BUILD_MODE -- $*
}

trap cleanup SIGHUP SIGINT SIGTERM EXIT

git clone $SIGNIFY_REPO || true
pushd signify
git reset --hard
git pull
git submodule update --init
rm -rf libbsd-*
make clean all \
  BUNDLED_LIBBSD=1 \
  BUNDLED_LIBBSD_VERIFY_GPG=0 \
  LIBBSD_LDFLAGS="-lrt" \
  WGET="wget --no-check-certificate"
popd

SIGNIFY=$(pwd)/signify/signify

echo "==> Testing Rust Generate/Sign, C Verify"
cargo_run -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo_run -S -s $PRIV -m $MSG -x ${MSG}.sig
$SIGNIFY -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Testing Rust Generate, C Sign/Verify"
cargo_run -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
$SIGNIFY -S -s $PRIV -m $MSG -x ${MSG}.sig
$SIGNIFY -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Testing Rust Generate, C Sign, Rust Verify"
cargo_run -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
$SIGNIFY -S -s $PRIV -m $MSG -x ${MSG}.sig
cargo_run -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Testing C Generate/Sign, Rust Verify"
$SIGNIFY -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
$SIGNIFY -S -s $PRIV -m $MSG -x ${MSG}.sig
cargo_run -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Testing C Generate, Rust Sign/Verify"
$SIGNIFY -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo_run -S -s $PRIV -m $MSG -x ${MSG}.sig
cargo_run -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Testing C Generate, Rust Sign, C Verify"
$SIGNIFY -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo_run -S -s $PRIV -m $MSG -x ${MSG}.sig
$SIGNIFY -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

printf "\n\033[1;37m\\o/ \033[0;32mAll tests passed without errors!\033[0m\n"

exit 0
