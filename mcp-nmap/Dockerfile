FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/mcp-nmap ./cmd/mcp-nmap

FROM alpine:3.21
RUN apk add --no-cache ca-certificates nmap \
    && update-ca-certificates
RUN adduser -D -u 1000 mcpuser
USER mcpuser
WORKDIR /app
COPY --from=builder /out/mcp-nmap /usr/local/bin/mcp-nmap
ENTRYPOINT ["/usr/local/bin/mcp-nmap"]
