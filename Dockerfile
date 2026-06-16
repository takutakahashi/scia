FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /out/scia ./cmd/scia

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /tmp
COPY --from=build /out/scia /scia
COPY configs/example.yaml /configs/example.yaml
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/scia"]
