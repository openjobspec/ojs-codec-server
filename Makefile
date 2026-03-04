.PHONY: build run test lint clean docker-build

BINARY := bin/ojs-codec-server

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
	docker build -t ojs-codec-server .
