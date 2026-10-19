# Run this build on a larger external builder, not the 512 MiB server.
FROM rust:1.98.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release && mkdir /out && cp target/release/mail-bridge-rust /out/

# Export a Debian 12 x86_64 executable with buildx --target binary --output.
FROM scratch AS binary
COPY --from=build /out/mail-bridge-rust /mail-bridge-rust

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 && rm -rf /var/lib/apt/lists/* && mkdir /data && chown 10001:10001 /data
COPY --from=build /out/mail-bridge-rust /usr/local/bin/mail-bridge-rust
USER 10001:10001
ENV MAIL_BRIDGE_BIND=0.0.0.0:18765 MAIL_BRIDGE_DATA_DIR=/data
EXPOSE 18765
ENTRYPOINT ["/usr/local/bin/mail-bridge-rust"]
