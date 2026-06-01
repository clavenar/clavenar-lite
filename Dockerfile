# syntax=docker/dockerfile:1.7
#
# Multi-stage build for clavenar-lite. Stage 1 produces the release
# binary against rust:1-bookworm; stage 2 lands the binary on
# debian:bookworm-slim with the bundled default policies and runs
# under the standard distroless-ish nonroot UID 65532.
#
# Built artifact runs on port 8088 by default; mount a policy
# directory or use the bundled governance.rego baseline. SQLite
# ledger defaults to :memory: so the container is stateless out of
# the box — set CLAVENAR_LITE_LEDGER=/var/lib/clavenar-lite/ledger.db and
# bind-mount a volume for persistence.

# ---------- builder ----------
FROM rust:1-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY policies ./policies

# Build the release binary. Docker's layer cache keeps the COPY +
# `cargo fetch`-warmed dependency graph hot across rebuilds that only
# change source files, so iteration is cheap after the first build.
RUN cargo build --release --locked --bin clavenar-lite

# ---------- runtime ----------
FROM debian:bookworm-slim AS runtime

# ca-certificates so reqwest can do TLS to upstream APIs; tini as
# PID 1 for clean signal handling in container runtimes that don't
# forward SIGTERM correctly. libsqlite is statically linked into the
# binary via rusqlite/bundled — no system sqlite needed.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        tini && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /etc/clavenar-lite/policies /var/lib/clavenar-lite && \
    chown -R 65532:65532 /var/lib/clavenar-lite

COPY --from=builder /build/target/release/clavenar-lite /usr/local/bin/clavenar-lite
COPY --from=builder /build/policies /etc/clavenar-lite/policies

USER 65532:65532

# Read every knob from env so a `fly secrets set CLAVENAR_LITE_TOKEN=...`
# or `docker run -e CLAVENAR_LITE_UPSTREAM_URL=...` works without an
# argv override. CLI flags still win when passed.
#
# CLAVENAR_LITE_MODE defaults to observe so a bare
# `docker run ghcr.io/clavenar/clavenar-lite:latest` boots without
# 403-ing the first request — the 60-second-deploy promise in the
# README. fly.toml and the static-binary snippet also default to
# observe; flip to enforce via `fly secrets set` / `docker run -e` /
# `--mode enforce` once verdicts are trustworthy.
ENV CLAVENAR_LITE_PORT=8088 \
    CLAVENAR_LITE_POLICY_DIR=/etc/clavenar-lite/policies \
    CLAVENAR_LITE_LEDGER=:memory: \
    CLAVENAR_LITE_MODE=observe \
    RUST_LOG=info

EXPOSE 8088

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/clavenar-lite"]
CMD ["start"]
