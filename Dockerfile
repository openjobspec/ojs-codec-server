FROM golang:1.26.6-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY *.go ./

RUN CGO_ENABLED=0 go build -o /ojs-codec-server .

FROM alpine:3.20
ARG VERSION
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/openjobspec/ojs-codec-server" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apk --no-cache add ca-certificates \
    && addgroup -S ojs && adduser -S ojs -G ojs
COPY --from=builder /ojs-codec-server /usr/local/bin/ojs-codec-server

USER ojs
EXPOSE 8089

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8089/health || exit 1

ENTRYPOINT ["ojs-codec-server"]
