# syntax=docker/dockerfile:1

# Builds vpsguard as a static binary and ships it in a minimal image with
# just enough on top for `vpsguard fleet` (an ssh client) and TLS-verified
# HTTP (ca-certificates, for `vpsguard update`). Meant for running
# audit/harden/fleet from CI without installing the binary on the runner
# -- see the GitHub Action (vpsguard-action) for a wrapper around this.
FROM golang:1.22-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -X github.com/salamancacm/vpsguard/cmd.Version=${VERSION}" \
    -o /out/vpsguard .

FROM alpine:3.20

RUN apk add --no-cache openssh-client ca-certificates

COPY --from=build /out/vpsguard /usr/local/bin/vpsguard

ENTRYPOINT ["vpsguard"]
CMD ["--help"]
