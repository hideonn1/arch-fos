.PHONY: all check build openapi web-build clean

all: check build

openapi:
	cargo run -p arch-fos-api -- --dump-openapi > web/openapi.json
	npm --prefix web run gen:api

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	npm --prefix web run typecheck

web-build:
	npm --prefix web run build

build: openapi web-build
	cargo build --workspace --release

clean:
	cargo clean
	rm -rf web/dist
