VERSION ?= $(shell cat VERSION)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE ?= ghcr.io/takutakahashi/scia

.PHONY: test build image release-check

test:
	go test ./...

build:
	go build -trimpath -ldflags="-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)" -o bin/scia ./cmd/scia

image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t $(IMAGE):$(VERSION) .

release-check:
	@case "$(VERSION)" in v*) echo "VERSION must be semantic without v prefix, e.g. 1.2.3"; exit 1;; *.*.*) ;; *) echo "VERSION must be semantic, e.g. 1.2.3"; exit 1;; esac
