#!/usr/bin/env bash
set -euo pipefail

# Pin the artifact and its digest together when publishing a new version.
url='https://raw.githubusercontent.com/TianWen6654/Xray-go-XHTTP/b4055f10226678ab657c6537989c6d5299a14812/nat-relay/nat-relay.sh'
digest='927e41ca3aa520dfb3ea7a9a7c3463947840b4bb0a924ce294db6547fb88df4a'

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
    trap - EXIT
    printf '已校验并保存到 %s\n' "$target"
    if [[ ${1:-} == --download-only ]]; then return 0; fi
    if [[ ! -t 0 ]] && ( : </dev/tty ) 2>/dev/null; then
        exec bash "$target" "$@" </dev/tty
    else
        exec bash "$target" "$@"
    fi
}

download "$@"
