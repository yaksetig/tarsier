# ByMC (Byzantine Model Checker) Docker image
# Pinned to bymc-2.4.2 for reproducible verification runs.
#
# Build:   docker build -t tarsier-bymc:latest benchmarks/bymc/
# Run:     docker run --rm -v "$PWD":/work tarsier-bymc:latest /work/model.ta all

FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    libffi-dev \
    libgmp-dev \
    libopenmpi-dev \
    m4 \
    openmpi-bin \
    pkg-config \
    python \
    python3 \
    unzip \
    wget \
  && rm -rf /var/lib/apt/lists/*

# Install opam 2.x without invoking the interactive installer prompt.
RUN curl -fsSL -o /usr/local/bin/opam \
      https://github.com/ocaml/opam/releases/download/2.1.5/opam-2.1.5-x86_64-linux && \
    chmod +x /usr/local/bin/opam && \
    opam --version

# Initialize opam with OCaml 4.06.1 (last version well-supported by ByMC)
RUN opam init --disable-sandboxing --bare -y && \
    opam switch create 4.06.1 ocaml-base-compiler.4.06.1 && \
    eval $(opam env)

# Older OCaml packages for 4.06 live in opam's archive repository.
RUN eval $(opam env) && \
    opam repository add archive git+https://github.com/ocaml/opam-repository-archive -y

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
      batteries \
      ocamlbuild \
      ocamlgraph \
      sexplib \
      lazy-trie \
      z3 \
      ctypes \
      ctypes-foreign

RUN eval $(opam env) && \
    opam install -y batteries.2.10.0

RUN eval $(opam env) && \
    opam install -y menhir.20181113

# ByMC requires the findlib package "mpi"; ocamlmpi is pinned from upstream.
RUN eval $(opam env) && \
    opam pin add -y -n ocamlmpi \
      git+https://github.com/xavierleroy/ocamlmpi.git#de777e4e2e74d37c560c0776b74261724c028716 && \
    opam install -y --no-depexts ocamlmpi

# Clone and build ByMC at pinned tag
RUN eval $(opam env) && \
    git clone --depth 1 --branch bymc-2.4.2 https://github.com/konnov/bymc.git /opt/bymc && \
    cd /opt/bymc/bymc && \
    make

ENV PATH="/opt/bymc/bymc:${PATH}"

ENTRYPOINT ["/opt/bymc/bymc/verifypa-schema"]
