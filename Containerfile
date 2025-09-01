FROM docker.io/library/rust:trixie as build

COPY . /src
WORKDIR /src
RUN cargo build --release

FROM quay.io/fedora/fedora:42
COPY --from=build /src/target/release/clevis-pin-trustee /usr/bin/clevis-pin-trustee
COPY --from=build /src/clevis-encrypt-trustee /usr/bin/clevis-encrypt-trustee
COPY --from=build /src/clevis-decrypt-trustee /usr/bin/clevis-decrypt-trustee
