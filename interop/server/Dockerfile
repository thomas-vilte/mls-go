FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum* ./
COPY interop/server/go.mod interop/server/go.sum* ./interop/server/

RUN go mod download || true
RUN cd interop/server && go mod download || true

COPY . .

WORKDIR /app/interop/server

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mls-mock-client .

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/interop/server/mls-mock-client .

EXPOSE 50051

ENTRYPOINT ["./mls-mock-client"]
CMD ["-port", "50051"]
