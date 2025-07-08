FROM golang:1.23.0 AS build

WORKDIR /app

COPY . .
RUN \
go env && \
go mod init cealingdns && \
go mod tidy && \
CGO_ENABLED=0 GOOS=linux go build -a -ldflags "-s -w" -v -o cealingdns 

FROM alpine/k8s:1.22.10
RUN apk add --no-cache curl jq
COPY --from=build /app/cealingdns  /app/config.json /
CMD ["/cealingdns"]