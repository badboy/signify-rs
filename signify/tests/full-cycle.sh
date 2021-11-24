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

trap cleanup SIGHUP SIGINT SIGTERM EXIT

echo "==> Normal Cycle"
cargo_run -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo_run -S -s $PRIV -m $MSG -x ${MSG}.sig
cargo_run -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Cycle (embedded)"
cargo_run -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo_run -S -e -s $PRIV -m $MSG
cargo_run -V -e -p $PUB -m $MSG

MSG_SIZE=$(wc -c $MSG | awk '{print $1}')
SIG_SIZE=$(wc -c $MSG.sig | awk '{print $1}')
[ $SIG_SIZE -gt $MSG_SIZE ]

cleanup

printf "\n\033[1;37m\\o/ \033[0;32mAll tests passed without errors!\033[0m\n"

exit 0
