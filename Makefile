
all: build

build:
	cargo build

release:
	cargo build --release

run:
	cargo run

test: build
	cargo test

format:
	rustfmt src/*

format-check:
	cargo fmt --all -- --check

