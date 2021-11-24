#!/bin/bash

set -e

pushd $(dirname $0) > /dev/null
SCRIPTPATH=$(pwd)
popd > /dev/null
cd $SCRIPTPATH

PUB=$(mktemp -u pub.$$.XXXXXXXXXX)
PRIV=$(mktemp -u priv.$$.XXXXXXXXXX)
MSG=$(mktemp -u msg.$$.XXXXXXXXXX)

cleanup() {
  rm -f $PUB $PRIV $MSG $MSG.sig || true
}

cargo_run() {
  cargo run -q $BUILD_MODE -- $*
}

assert_false() {
    set +e
    $*
    res=$?
    set -e
    [ $res -ne 0 ]
}

trap cleanup SIGHUP SIGINT SIGTERM EXIT

echo "==> Message modified"
cargo_run -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo_run -S -s $PRIV -m $MSG -x ${MSG}.sig
head -c 1 /dev/urandom >> $MSG
assert_false cargo_run -V -p $PUB -m $MSG -x ${MSG}.sig
cp ${MSG}.sig ${MSG}.sig.2
cleanup

echo "==> Signature modified"
cargo_run -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo_run -S -s $PRIV -m $MSG -x ${MSG}.sig
mv ${MSG}.sig.2 ${MSG}.sig
assert_false cargo_run -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Embedded Message modified"
cargo_run -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo_run -S -e -s $PRIV -m $MSG
rm $MSG
head -c 1 /dev/urandom >> ${MSG}.sig
assert_false cargo_run -V -e -p $PUB -m $MSG
cleanup

printf "\n\033[1;37m\\o/ \033[0;32mAll tests passed without errors!\033[0m\n"

exit 0
