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

trap cleanup SIGHUP SIGINT SIGTERM EXIT

echo "==> Normal Cycle"
cargo run -- -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo run -- -S -s $PRIV -m $MSG -x ${MSG}.sig
cargo run -- -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Cycle (embedded)"
cargo run -- -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo run -- -S -e -s $PRIV -m $MSG
cargo run -- -V -e -p $PUB -m $MSG

MSG_SIZE=$(wc -c $MSG | awk '{print $1}')
SIG_SIZE=$(wc -c $MSG.sig | awk '{print $1}')
[ $SIG_SIZE -gt $MSG_SIZE ]

cleanup


exit 0
