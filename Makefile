test: build cargo-test full-cycle integration

build:
	cargo build $(BUILD_MODE)

cargo-test:
	cargo test

full-cycle:
	bash ./signify/tests/full-cycle.sh

integration:
	bash ./signify/tests/integration.sh

compare:
	bash ./signify/tests/compare.sh
