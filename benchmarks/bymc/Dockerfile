# ByMC (Byzantine Model Checker) Docker image
# Pinned to v2.4.4 for reproducible verification runs.
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
    m4 \
    pkg-config \
    python3 \
    unzip \
    wget \
  && rm -rf /var/lib/apt/lists/*

# Install opam 2.x
RUN curl -fsSL https://raw.githubusercontent.com/ocaml/opam/master/shell/install.sh | \
    sh -s -- --version 2.1.5

# Initialize opam with OCaml 4.06.1 (last version well-supported by ByMC)
RUN opam init --disable-sandboxing --bare -y && \
    opam switch create 4.06.1 && \
    eval $(opam env)

# Install Z3 4.8.7 from GitHub release
RUN wget -q https://github.com/Z3Prover/z3/releases/download/z3-4.8.7/z3-4.8.7-x64-ubuntu-16.04.zip \
    -O /tmp/z3.zip && \
    unzip -q /tmp/z3.zip -d /opt && \
    mv /opt/z3-4.8.7-x64-ubuntu-16.04 /opt/z3 && \
    rm /tmp/z3.zip

ENV PATH="/opt/z3/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/z3/bin:${LD_LIBRARY_PATH}"

# Install OCaml dependencies via opam
RUN eval $(opam env) && \
    opam install -y \
      batteries \
      ocamlgraph \
      sexplib \
      ctypes \
      ctypes-foreign

# Clone and build ByMC at pinned tag
RUN eval $(opam env) && \
    git clone --depth 1 --branch v2.4.4 https://github.com/konnov/bymc.git /opt/bymc && \
    cd /opt/bymc/bymc && \
    make

ENV PATH="/opt/bymc/bymc:${PATH}"

ENTRYPOINT ["/opt/bymc/bymc/verifypa-schema"]
