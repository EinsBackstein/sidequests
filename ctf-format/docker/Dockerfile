# The `.ctf` challenge base image (spec §31, ticket 67).
#
# A challenge that declares `runtime` runs on this image: it carries the
# `ctf-generator` host, reads the per-subject seed the platform injects, and writes
# the generated artifacts to the data mount. A challenge that does not need a
# generator (OSINT, most crypto) does not use this image at all.
#
# Build from the `ctf-format/` directory:
#
#   docker build -f docker/Dockerfile -t ctf-challenge-base .
#
# The builder tag must match `rust-toolchain.toml` (1.97.1): generator determinism
# is only meaningful relative to a pinned toolchain (spec §23.5).
FROM rust:1.97.1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p ctf-generator --bin ctf-generator

# The runtime image is minimal and non-root. The platform MUST also run it with a
# read-only root filesystem and the two documented mounts; see docker/README.md.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/ctf-generator /usr/local/bin/ctf-generator
USER nonroot
ENTRYPOINT ["/usr/local/bin/ctf-generator"]
