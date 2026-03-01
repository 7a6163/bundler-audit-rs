FROM rust:1 AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && strip target/release/gem-audit

# -----------------------------------------------------------
# Use the debug variant which includes busybox (/bin/sh) for CI compatibility
FROM gcr.io/distroless/cc-debian13:debug

COPY --from=builder /build/target/release/gem-audit /usr/local/bin/gem-audit

# Pre-create a writable directory for the advisory database.
# Override with GEM_AUDIT_DB (e.g. in GitLab CI point to $CI_PROJECT_DIR).
RUN ["/busybox/mkdir", "-p", "/db"]
ENV GEM_AUDIT_DB=/db

WORKDIR /workspace

ENTRYPOINT ["gem-audit"]
CMD ["check", "--update"]
