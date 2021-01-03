FROM golang:1.15.3-alpine3.12 as builder

WORKDIR /build
COPY go.mod .
COPY go.sum .
COPY main.go .
COPY internal internal

RUN CGO_ENABLED=0 go build -o app main.go
FROM alpine
COPY --from=builder /build/app .
COPY internal/http/html client/internal/http/html
ENTRYPOINT ["./app"]