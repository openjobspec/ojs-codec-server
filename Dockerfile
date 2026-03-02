FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY *.go ./

RUN CGO_ENABLED=0 go build -o /ojs-codec-server .

FROM alpine:3.20

RUN apk --no-cache add ca-certificates
COPY --from=builder /ojs-codec-server /usr/local/bin/ojs-codec-server

EXPOSE 8089

ENTRYPOINT ["ojs-codec-server"]
