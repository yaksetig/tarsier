FROM rust:1.92-bookworm AS builder

ENV CMAKE_POLICY_VERSION_MINIMUM=3.5
ENV CARGO_TERM_COLOR=always

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake clang libclang-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --release -p tarsier-cli -p tarsier-certcheck

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libgomp1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/tarsier /usr/local/bin/tarsier
COPY --from=builder /src/target/release/tarsier-certcheck /usr/local/bin/tarsier-certcheck

ENTRYPOINT ["tarsier"]
