FROM rust:1.92-bookworm AS builder

ENV CMAKE_POLICY_VERSION_MINIMUM=3.5
ENV CARGO_TERM_COLOR=always

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake clang libclang-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --release -p tarsier-playground

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libgomp1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/tarsier-playground /usr/local/bin/tarsier-playground

ENV TARSIER_PLAYGROUND_HOST=0.0.0.0
ENV TARSIER_PLAYGROUND_PORT=7878

EXPOSE 7878

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
  CMD curl -fsS http://127.0.0.1:7878/api/health || exit 1

ENTRYPOINT ["tarsier-playground"]
