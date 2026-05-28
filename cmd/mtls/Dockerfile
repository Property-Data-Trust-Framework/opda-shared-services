# Build stage
FROM golang:1.24-alpine AS builder

ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

COPY cmd/mtls/entrypoint.sh ./entrypoint.sh

RUN go build -o main ./cmd/mtls

# Run stage
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/main ./main
COPY --from=builder /app/entrypoint.sh ./entrypoint.sh
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

RUN apk add --no-cache aws-cli

RUN chmod +x ./entrypoint.sh

EXPOSE 443

ENTRYPOINT ["/bin/sh", "./entrypoint.sh"]
CMD ["./main"]
