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

assert_false() {
    set +e
    $*
    res=$?
    set -e
    [ $res -ne 0 ]
}

trap cleanup SIGHUP SIGINT SIGTERM EXIT

echo "==> Message modified"
cargo run -q -- -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo run -q -- -S -s $PRIV -m $MSG -x ${MSG}.sig
head -c 1 /dev/urandom >> $MSG
assert_false cargo run -q -- -V -p $PUB -m $MSG -x ${MSG}.sig
cp ${MSG}.sig ${MSG}.sig.2
cleanup

echo "==> Signature modified"
cargo run -q -- -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo run -q -- -S -s $PRIV -m $MSG -x ${MSG}.sig
mv ${MSG}.sig.2 ${MSG}.sig
assert_false cargo run -q -- -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Embedded Message modified"
cargo run -q -- -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo run -q -- -S -e -s $PRIV -m $MSG
rm $MSG
head -c 1 /dev/urandom >> ${MSG}.sig
assert_false cargo run -q -- -V -e -p $PUB -m $MSG
cleanup

exit 0
