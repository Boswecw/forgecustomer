# Multi-stage build for the ForgeCustomer API.
FROM rust:1-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY api ./api
RUN cargo build --release --bin forgecustomer-api

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/forgecustomer-api /usr/local/bin/forgecustomer-api
# Configuration is provided via environment variables (see .env.example). No secrets are
# baked into the image.
EXPOSE 8080
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/forgecustomer-api"]
