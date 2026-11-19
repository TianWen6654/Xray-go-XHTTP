#!/usr/bin/env bash
set -euo pipefail

# Pin the artifact and its digest together when publishing a new version.
url='https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/082c86d327b01b5224d8dadc81365f717a6466b4/nat-relay/nat-relay.sh'
digest='052d3723d9ffadf776157e01d9afb7aebb84c72fed8bb4dbf3cd50e1ac8e58ef'

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
    if [[ ! -t 0 ]] && ( : </dev/tty ) 2>/dev/null; then
        bash "$target" "$@" </dev/tty
    else
        bash "$target" "$@"
    fi
}

download "$@"
