FROM rust:latest

# Install packages
RUN apt update
RUN apt upgrade -y
RUN apt install -y bpftool
RUN apt install -y build-essential
RUN apt install -y iputils-ping
RUN apt install -y libclang-19-dev
RUN apt install -y libpolly-19-dev
RUN apt install -y linux-perf
RUN apt install -y llvm-19-dev

# Configure Rust toolchain
RUN rustup self update
RUN rustup default nightly
RUN rustup component add clippy
RUN rustup component add rust-analyzer
RUN rustup component add rust-src
RUN rustup component add rustfmt

# Install Rust binaries
RUN cargo install bpf-linker
RUN cargo install cargo-edit
RUN cargo install cargo-generate
RUN cargo install flamegraph

# Install Helix
WORKDIR /root/.config/helix
ARG HELIX_VERSION=25.07.1
ARG HELIX_BUILD=helix-${HELIX_VERSION}-aarch64-linux
ARG HELIX_TARBALL=${HELIX_BUILD}.tar.xz
ADD https://github.com/helix-editor/helix/releases/download/${HELIX_VERSION}/${HELIX_TARBALL} .
RUN tar -xf $HELIX_TARBALL
RUN rm $HELIX_TARBALL
RUN mv ${HELIX_BUILD}/hx /usr/bin/
RUN mv ${HELIX_BUILD}/runtime .
RUN rm -rf $HELIX_BUILD

# Copy fayawall
WORKDIR /usr/src/fayawall
COPY . .
