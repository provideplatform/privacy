.PHONY: build clean install lint link-zokrates migrate mod test zokrates

default: build

clean:
	rm -rf ./.bin 2>/dev/null || true
	go fix ./...
	go clean -i ./...

build: mod clean
	go fmt ./...
	go build -v -o ./.bin/api ./cmd/api
	go build -v -o ./.bin/consumer ./cmd/consumer
	go build -v -o ./.bin/migrate ./cmd/migrate

install: clean
	go install ./...

link-zokrates:
	go tool link -o go-zkp -extld clang -linkmode external -v zokrates.a

lint:
	./ops/lint.sh

migrate: mod
	rm -rf ./.bin/privacy_migrate 2>/dev/null || true
	go build -v -o ./.bin/privacy_migrate ./cmd/migrate
	./ops/migrate.sh

mod:
	go mod init 2>/dev/null || true
	go mod tidy
	go mod vendor

run_local_dependencies:
	./ops/run_local_dependencies.sh

stop_local_dependencies:
	./ops/stop_local_dependencies.sh

test: build
	./ops/run_local_tests.sh

integration: build
	./ops/run_integration_tests.sh

zokrates:
	@rm -rf .tmp/zokrates
	@mkdir -p .tmp/
	git clone --single-branch --branch makefile git@github.com:kthomas/zokrates.git .tmp/zokrates
	@pushd .tmp/zokrates && make static && popd
	@echo TODO... hoist built zokrates artifacts for linking...
