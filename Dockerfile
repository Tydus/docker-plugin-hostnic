FROM golang:1.12.0-alpine3.9 AS builder

WORKDIR /app

RUN apk --update add git
ENV GO111MODULE=on

COPY go.mod go.sum ./
RUN go mod download

ADD . .
RUN GOBIN=/app/bin go install .

FROM alpine:3.9
MAINTAINER jolestar <jolestar@gmail.com>

COPY --from=builder /app/bin/docker-plugin-hostnic /usr/bin/

VOLUME /run/docker/plugins
VOLUME /etc/docker/hostnic

CMD ["/usr/bin/docker-plugin-hostnic"]
