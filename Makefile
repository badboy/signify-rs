test: build cargo-test full-cycle integration

build:
	cargo build $(BUILD_MODE)

cargo-test:
	cargo test

full-cycle:
	./tests/full-cycle.sh

integration:
	./tests/integration.sh

compare:
	./tests/compare.sh
