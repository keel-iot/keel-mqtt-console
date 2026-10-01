IMAGE ?= keel-mqtt-console:dev

.PHONY: test build docker-build helm-lint

test:
	go test ./...

build:
	go build -trimpath -o bin/keel-mqtt-console ./cmd/console

docker-build:
	docker build -t $(IMAGE) .

helm-lint:
	helm lint deploy/helm/keel-mqtt-console
