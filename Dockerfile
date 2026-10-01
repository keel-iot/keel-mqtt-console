FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/keel-mqtt-console ./cmd/console

FROM alpine:3.22
RUN addgroup -S console && adduser -S -G console console
COPY --from=build /out/keel-mqtt-console /usr/local/bin/keel-mqtt-console
USER console
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/keel-mqtt-console"]
