FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/keel-mqtt-console ./cmd/console

FROM alpine:3.22
RUN addgroup -S -g 65532 console && adduser -S -D -H -u 65532 -G console console
COPY --from=build /out/keel-mqtt-console /usr/local/bin/keel-mqtt-console
# Keep the image user numeric so Kubernetes can verify runAsNonRoot without
# having to resolve the username from /etc/passwd.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/keel-mqtt-console"]
