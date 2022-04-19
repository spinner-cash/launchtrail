CANISTER_INFO=dist/canister-info
LAUNCH_TRAIL=dist/launch-trail.wasm dist/launch-trail.did
HELLO=dist/hello.wasm dist/hello.did
TESTS=configure install
ARGUMENT=(record {bucket_size = 1000 : nat64; max_buckets = 1000 : nat64; config = record { revokers = vec { principal "SUBMITTER" }; submitters = vec { principal "SUBMITTER" }; min_schedule = 0 : nat64;}})
CARGO_BUILD?=release
CARGO_FLAGS?=--release

default: $(LAUNCH_TRAIL) $(HELLO) dist/canister-info

release:
	$(MAKE) CARGO_FLAGS="--release --locked" CARGO_BUILD=release $(LAUNCH_TRAIL) $(CANISTER_INFO)

dist:
	mkdir -p dist

target/wasm32-unknown-unknown/$(CARGO_BUILD)/%.wasm: src/%.rs
	cargo build $(CARGO_FLAGS) --target=wasm32-unknown-unknown --bin $(subst src/,,$(subst .rs,,$<))

dist/%.wasm: target/wasm32-unknown-unknown/$(CARGO_BUILD)/%.wasm | dist
	wasm-opt -O2 $< -o $@

target/$(CARGO_BUILD)/canister-info: src/canister-info.rs
	cargo build $(CARGO_FLAGS) --bin canister-info

dist/canister-info: target/$(CARGO_BUILD)/canister-info | dist
	cp $< $@

dist/%.did: dist/%.wasm | dist
	cargo run $(CARGO_FLAGS) --bin $(subst dist/,,$(subst .wasm,,$<)) > $@

dist/seed.txt: | dist
	keysmith generate -o $@

dist/private.pem: dist/seed.txt | dist
	keysmith private-key -f $< -o $@

dfx.json:
	echo '{"canisters":{"launch-trail":{"type":"custom","candid":"dist/launch-trail.did","wasm":"dist/launch-trail.wasm","build":""}}}' > $@

deploy: dfx.json
	dfx deploy launch-trail $(OPTS) --argument "$$(echo '$(ARGUMENT)'|sed -e "s/SUBMITTER/$$(dfx identity get-principal)/g")"

test: default dist/private.pem
	cd tests && ./run.sh $(TESTS)

clean:
	rm -rf dist
	rm -f target
	rm -rf test/test-????????.repl test/config.dhall

.PHONY: default release test deploy clean
