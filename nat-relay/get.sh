#!/usr/bin/env bash
set -euo pipefail

# Pin the artifact and its digest together when publishing a new version.
url='https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/414888b94a3ec120ffda222f9bb5d1dcd147e955/nat-relay/nat-relay.sh'
digest='29f03ff6e86d885811c2d493f932d31a53c29b0332aa59bd8fbbaf3b1d0d7290'

download() {
    local target="$HOME/nat-relay.sh"
    stage=$(mktemp -- "$HOME/.nat-relay.XXXXXXXX")
    trap 'rm -f -- "$stage"' EXIT
    if command -v curl >/dev/null; then
        curl --fail --silent --show-error --location --retry 2 --connect-timeout 15 --max-time 120 --output "$stage" "$url"
    elif command -v wget >/dev/null; then
        wget -nv --tries=3 --timeout=30 -O "$stage" "$url"
    else
        printf '%s\n' '请先安装 curl 或 wget。' >&2
        return 1
    fi
    printf '%s  %s\n' "$digest" "$stage" | sha256sum --check --status || {
        printf '%s\n' '下载文件的 SHA-256 校验失败。' >&2
        return 1
    }
    mv -fT -- "$stage" "$target"
    printf '已校验并保存到 %s\n' "$target"
    if [[ ${1:-} == --download-only ]]; then return 0; fi
    if [[ $# == 0 && ! -t 0 ]]; then
        # The interactive installer reads its menu from the user's terminal.
        bash "$target" </dev/tty
    else
        bash "$target" "$@"
    fi
}

download "$@"
