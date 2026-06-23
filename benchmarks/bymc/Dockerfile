# ByMC (Byzantine Model Checker) Docker image
# Pinned to bymc-2.4.2 for reproducible verification runs.
#
# Build:   docker build -t tarsier-bymc:latest benchmarks/bymc/
# Run:     docker run --rm -v "$PWD":/work tarsier-bymc:latest /work/model.ta all

FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ARG OPAM_VERSION=2.1.5
ARG OPAM_REPOSITORY_REF=2026-05-before-lower-bound-ocaml411

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    libffi-dev \
    libgmp-dev \
    m4 \
    mpi-default-dev \
    pkg-config \
    python2.7 \
    python3 \
    unzip \
    wget \
  && rm -rf /var/lib/apt/lists/*

# Install a pinned opam binary instead of streaming the mutable installer script.
RUN curl -fsSL \
    "https://github.com/ocaml/opam/releases/download/${OPAM_VERSION}/opam-${OPAM_VERSION}-x86_64-linux" \
    -o /usr/local/bin/opam && \
    chmod +x /usr/local/bin/opam && \
    opam --version

# Initialize opam with OCaml 4.06.1 (last version well-supported by ByMC)
RUN opam init --disable-sandboxing --bare -y --shell=sh \
      default "https://github.com/ocaml/opam-repository.git#${OPAM_REPOSITORY_REF}" && \
    opam switch create 4.06.1 ocaml-base-compiler.4.06.1 -y && \
    eval $(opam env)

# Install Z3 4.8.7 from GitHub release
RUN wget -q https://github.com/Z3Prover/z3/releases/download/z3-4.8.7/z3-4.8.7-x64-ubuntu-16.04.zip \
    -O /tmp/z3.zip && \
    unzip -q /tmp/z3.zip -d /opt && \
    mv /opt/z3-4.8.7-x64-ubuntu-16.04 /opt/z3 && \
    rm /tmp/z3.zip

ENV PATH="/opt/z3/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/z3/bin"

# Install OCaml dependencies via opam
RUN eval $(opam env) && \
    opam install -y \
      ocamlbuild \
      menhir.20181113 \
      batteries \
      ocamlgraph \
      sexplib \
      lazy-trie.1.2.0 \
      mpi.1.07 \
      z3.4.8.7 \
      ctypes \
      ctypes-foreign

# Clone and build ByMC at pinned tag
RUN eval $(opam env) && \
    git clone --depth 1 --branch bymc-2.4.2 https://github.com/konnov/bymc.git /opt/bymc && \
    cd /opt/bymc/bymc && \
    make

ENV PATH="/opt/bymc/bymc:${PATH}"

ENTRYPOINT ["/opt/bymc/bymc/verifypa-schema"]
