# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-bookworm AS agent-build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/oncache-agent ./cmd/oncache-agent

FROM ubuntu:24.04 AS bpf-build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        gcc \
        make \
        pkg-config \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY bpf ./bpf
RUN make -C bpf CLANG=clang LLC=llc BUILD_DIR=/out/bpf \
    && test -s /out/bpf/tc_prog_kern.o

FROM ubuntu:22.04

ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
        linux-tools-generic \
    && bpftool_path="$(find /usr/lib -type f -path '/usr/lib/linux-tools*/bpftool' -perm -111 -print -quit)" \
    && test -n "${bpftool_path}" \
    && install -m 0755 "${bpftool_path}" /usr/local/bin/bpftool \
    && rm -rf /var/lib/apt/lists/*

COPY --from=agent-build /out/oncache-agent /oncache-agent
COPY --from=bpf-build /out/bpf/tc_prog_kern.o /opt/oncache/bpf/tc_prog_kern.o

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

LABEL org.opencontainers.image.title="FNCache agent" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

ENTRYPOINT ["/oncache-agent"]
