# Builds the bseal fuzzers inside the OSS-Fuzz base-builder image.
#
# To pin: replace :latest with @sha256:<digest> after first successful build.
FROM gcr.io/oss-fuzz-base/base-builder:latest

# System dependencies: libsodium + OpenSSL development headers, plus build tooling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        ninja-build \
        pkg-config \
        libsodium-dev \
        libssl-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

# Copy the repository into $SRC (set by the base image) and initialise submodules.
COPY . $SRC/bseal
WORKDIR $SRC/bseal
RUN git submodule update --init --recursive || true

# The base image invokes /src/build.sh by convention.
COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
