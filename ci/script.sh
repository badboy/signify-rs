# This script takes care of testing your crate

set -ex

main() {
    cross build --target $TARGET

    if [ ! -z $DISABLE_TESTS ]; then
        return
    fi

    cross test --target $TARGET

    ./tests/full-cycle.sh
    ./tests/integration.sh

    if [ "$TARGET" = "x86_64-unknown-linux-gnu" ]; then
      ./tests/compare.sh
    fi
}

# we don't run the "test phase" when doing deploys
if [ -z $TRAVIS_TAG ]; then
    main
fi
