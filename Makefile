# All targets.
.PHONY: build

build: build-local

build-local:
	@go build -mod=vendor -v -o ./bin/genkc .                                                                               \

.PHONY: clean
clean:
	@-rm -vrf ./bin
