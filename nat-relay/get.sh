#!/usr/bin/env bash
set -euo pipefail

# Pin the artifact and its digest together when publishing a new version.
url='https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/04711587814d849224a21f45cd1e1242705d5f2e/nat-relay/nat-relay.sh'
digest='7fa162efb523de77815c147279624f8fd0028a83f3650e7debe09066d212abd3'

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
