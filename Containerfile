# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

FROM ghcr.io/confidential-clusters/buildroot:latest AS build

COPY . /src
WORKDIR /src
RUN cargo build --release -p clevis-pin-trustee

FROM scratch
COPY --from=build /src/target/release/clevis-pin-trustee /usr/bin/clevis-pin-trustee
COPY --from=build /src/clevis-encrypt-trustee /usr/bin/clevis-encrypt-trustee
COPY --from=build /src/clevis-decrypt-trustee /usr/bin/clevis-decrypt-trustee
