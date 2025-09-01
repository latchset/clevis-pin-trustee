FROM docker.io/library/rust:trixie as build

COPY . /src
WORKDIR /src
RUN cargo build --release

FROM quay.io/fedora/fedora:42
COPY --from=build /src/target/release/clevis-pin-trustee /usr/bin/clevis-pin-trustee
