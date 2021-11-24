test: build cargo-test full-cycle integration

build:
	cargo build $(BUILD_MODE)

cargo-test:
	cargo test

full-cycle:
	./signify/tests/full-cycle.sh

integration:
	./signify/tests/integration.sh

compare:
	./signify/tests/compare.sh
