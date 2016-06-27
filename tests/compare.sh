#!/bin/bash

set -e 

pushd $(dirname $0) > /dev/null
SCRIPTPATH=$(pwd)
popd > /dev/null
cd $SCRIPTPATH

SIGNIFY_REPO="https://github.com/aperezdc/signify"

PUB=$(mktemp -u pub.$$.XXXXXXXXXX)
PRIV=$(mktemp -u priv.$$.XXXXXXXXXX)
MSG=$(mktemp -u msg.$$.XXXXXXXXXX)

cleanup() {
  rm -f $PUB $PRIV $MSG $MSG.sig
}

trap cleanup SIGHUP SIGINT SIGTERM EXIT

git clone $SIGNIFY_REPO || true
pushd signify
git pull
make
popd

SIGNIFY=$(pwd)/$TMPDIR/signify/signify

echo "==> Testing Rust Generate/Sign, C Verify"
cargo run -q -- -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo run -q -- -S -s $PRIV -m $MSG -x ${MSG}.sig
$SIGNIFY -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Testing Rust Generate, C Sign/Verify"
cargo run -q -- -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
$SIGNIFY -S -s $PRIV -m $MSG -x ${MSG}.sig
$SIGNIFY -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Testing Rust Generate, C Sign, Rust Verify"
cargo run -q -- -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
$SIGNIFY -S -s $PRIV -m $MSG -x ${MSG}.sig
cargo run -q -- -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Testing C Generate/Sign, Rust Verify"
$SIGNIFY -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
$SIGNIFY -S -s $PRIV -m $MSG -x ${MSG}.sig
cargo run -q -- -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Testing C Generate, Rust Sign/Verify"
$SIGNIFY -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo run -q -- -S -s $PRIV -m $MSG -x ${MSG}.sig
cargo run -q -- -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup

echo "==> Testing C Generate, Rust Sign, C Verify"
$SIGNIFY -G -n -p $PUB -s $PRIV
head -c 100 /dev/urandom > $MSG
cargo run -q -- -S -s $PRIV -m $MSG -x ${MSG}.sig
$SIGNIFY -V -p $PUB -m $MSG -x ${MSG}.sig
cleanup
