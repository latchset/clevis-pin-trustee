#!/bin/bash
#
# SPDX-FileCopyrightText: Sergio Arroutbi <sarroutb@redhat.com>
#
# SPDX-License-Identifier: MIT

check() {
    require_binaries clevis-decrypt-trustee || return 1
    require_binaries clevis-pin-trustee || return 1
    require_binaries trustee-attester || return 1
    return 0
}

depends() {
    echo clevis network
    return 0
}

install() {
    inst_multiple \
        clevis-decrypt-trustee \
        clevis-pin-trustee \
        trustee-attester \
        curl
}
