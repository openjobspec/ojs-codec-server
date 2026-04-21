.PHONY: build run test lint clean docker-build

BINARY := bin/ojs-codec-server
VERSION ?= 0.5.0
IMAGE ?= ghcr.io/openjobspec/ojs-codec-server:v$(VERSION)

build:
	go build -o $(BINARY) .

run: build
	$(BINARY)

test:
	go test ./... -race -cover

lint:
	go vet ./...

clean:
	rm -rf bin/

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .
