FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /contextshield ./cmd/contextshield

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /etc/contextshield
COPY --from=build /contextshield /usr/local/bin/contextshield
COPY shield.yaml /etc/contextshield/shield.yaml
COPY rules /etc/contextshield/rules
EXPOSE 8080
ENTRYPOINT ["contextshield", "serve", "-config", "/etc/contextshield/shield.yaml"]
