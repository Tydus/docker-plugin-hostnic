FROM golang:1.12.0-alpine3.9 AS builder

ENV ORG_PATH "github.com/yunify"
ENV REPO_PATH "${ORG_PATH}/docker-plugin-hostnic"

RUN apk --update add bash git gcc
RUN apk add --update alpine-sdk
RUN apk add --update linux-headers

ADD . src/${REPO_PATH}

RUN go get "${REPO_PATH}"

FROM alpine:3.9
MAINTAINER jolestar <jolestar@gmail.com>

COPY --from=builder /go/bin/docker-plugin-hostnic /usr/bin/

VOLUME /run/docker/plugins
VOLUME /etc/docker/hostnic

CMD ["/usr/bin/docker-plugin-hostnic"]
