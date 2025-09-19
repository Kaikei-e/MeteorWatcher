# syntax=docker/dockerfile:1.7
FROM erlang:27-slim AS base

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PATH="/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

FROM base AS builder
RUN --mount=type=cache,target=/var/cache/apt \
  apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl git rebar3 xz-utils \
  && rm -rf /var/lib/apt/lists/*

ARG GLEAM_VERSION=1.12.0
RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
  amd64) gleam_arch=x86_64 ;; \
  arm64) gleam_arch=aarch64 ;; \
  *) echo "Unsupported arch: ${arch}" >&2; exit 1 ;; \
  esac; \
  # musl を先に試し、ダメなら gnu を試す
  for libc in unknown-linux-musl unknown-linux-gnu; do \
  base="https://github.com/gleam-lang/gleam/releases/download/v${GLEAM_VERSION}/gleam-v${GLEAM_VERSION}-${gleam_arch}-${libc}.tar.gz"; \
  sha="${base}.sha256"; \
  if curl -fsSL -o /tmp/gleam.tar.gz "$base"; then \
  # sha256 ファイル内の1列目（ハッシュ）だけ取り出し、/tmp/gleam.tar.gz に対して検証
  if curl -fsSL -o /tmp/gleam.sha256 "$sha"; then \
  expected="$(cut -d ' ' -f1 /tmp/gleam.sha256)"; \
  echo "${expected}  /tmp/gleam.tar.gz" | sha256sum -c -; \
  fi; \
  break; \
  fi; \
  done; \
  tar -xzf /tmp/gleam.tar.gz -C /usr/local/bin gleam; \
  chmod +x /usr/local/bin/gleam; \
  gleam --version

# non-root
RUN useradd -m -u 10001 app
USER app
WORKDIR /app

# （必要に応じて）依存キャッシュ最適化
# COPY --chown=app:app gleam.toml manifest.toml ./
# RUN gleam deps download

FROM builder AS dev
CMD ["sh", "-lc", "gleam --version && gleam deps download && gleam run"]
