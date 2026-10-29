#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

if [[ "${1:-}" == --cargo-plugin ]]; then
    printf '{"v":[1]}\n'
    IFS= read -r request
    if ! jq -e '
        .v == 1 and .kind == "get" and
        (.registry["index-url"] == "https://github.com/rust-lang/crates.io-index" or
         .registry["index-url"] == "sparse+https://index.crates.io/") and
        (.operation == "read" or
         (.operation == "publish" and
          .name == env.RELEASE_PUBLISH_PACKAGE and
          .vers == env.RELEASE_PUBLISH_VERSION and
          .cksum == env.RELEASE_PUBLISH_CHECKSUM and
          (.cksum | type == "string" and test("^[0-9a-f]{64}$"))))
    ' <<< "$request" > /dev/null; then
        echo "upload authorization rejected: package, version, registry, or archive checksum mismatch" >&2
        exit 1
    fi
    # Cargo requests read credentials before packaging. Never reuse them for publishing.
    jq -cn '
        if (env.RELEASE_PUBLISH_TOKEN // "") == "" then error("missing release token")
        else {Ok:{kind:"get",token:env.RELEASE_PUBLISH_TOKEN,
                  cache:"never",operation_independent:false}} end
    '
    exit 0
fi

if (($# != 3)); then
    echo "usage: publish-crate.sh PACKAGE VERSION ARCHIVE" >&2
    exit 1
fi
package=$1
version=$2
archive=$3
case "$package" in
    azure-tpm|azure-guest-attestation-sdk) ;;
    *) echo "unexpected release package: $package" >&2; exit 1 ;;
esac
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "invalid release version: $version" >&2
    exit 1
fi
if [[ ! -f "$archive" ]]; then
    echo "missing archive: $archive" >&2
    exit 1
fi
local_checksum=$(sha256sum "$archive")
local_checksum=${local_checksum%% *}
target_dir=${CARGO_TARGET_DIR:-target}
mkdir -p "$target_dir"
response_dir=$(mktemp -d "$target_dir/release-index.XXXXXX")
response="$response_dir/response"
trap 'rm -f "$response"; rmdir "$response_dir"' EXIT

registry_checksum() {
    local status
    if ! status=$(curl --silent --show-error --connect-timeout 10 --max-time 30 \
        --output "$response" --write-out '%{http_code}' \
        "https://index.crates.io/az/ur/$package"); then
        echo "registry request failed for $package $version" >&2
        return 1
    fi
    case "$status" in
        404) return 0 ;;
        200) ;;
        *) echo "registry returned HTTP $status for $package $version" >&2; return 1 ;;
    esac
    jq -r -s --arg version "$version" '
        if length == 0 then error("empty registry index")
        elif any(.[]; type != "object") then error("registry index records must be objects")
        elif any(.[]; (.vers | type) != "string") then
            error("registry index records must have a string vers")
        else . end |
        map(select(.vers == $version)) |
        if length == 0 then ""
        elif length != 1 then error("duplicate registry version")
        else .[0] |
            if .yanked == true then error("release version is yanked")
            elif .yanked != false then error("missing registry yanked status")
            elif (.cksum | type) != "string" then error("missing registry checksum")
            elif (.cksum | test("^[0-9a-f]{64}$") | not) then error("invalid registry checksum")
            else .cksum end
        end
    ' "$response"
}

verify_checksum() {
    if [[ "$1" != "$local_checksum" ]]; then
        echo "registry archive checksum mismatch for $package $version" >&2
        echo "local=$local_checksum registry=$1" >&2
        return 1
    fi
}

verify_repackaged_checksum() {
    local repackaged="$target_dir/package/$package-$version.crate"
    local checksum
    if [[ ! -f "$repackaged" ]]; then
        echo "missing repackaged archive: $repackaged" >&2
        return 1
    fi
    checksum=$(sha256sum "$repackaged")
    checksum=${checksum%% *}
    if [[ "$checksum" != "$local_checksum" ]]; then
        echo "repackaged archive checksum mismatch for $package $version" >&2
        echo "verified=$local_checksum repackaged=$checksum" >&2
        return 1
    fi
}

checksum=$(registry_checksum)
if [[ -n "$checksum" ]]; then
    verify_checksum "$checksum"
    echo "Already published $package $version; archive checksum matches"
    exit 0
fi

echo "Publishing $package $version"
cargo publish --locked --registry crates-io --dry-run -p "$package"
verify_repackaged_checksum
(
    export RELEASE_PUBLISH_TOKEN=${CARGO_REGISTRY_TOKEN:?missing crates.io release token}
    export RELEASE_PUBLISH_PACKAGE=$package RELEASE_PUBLISH_VERSION=$version
    export RELEASE_PUBLISH_CHECKSUM=$local_checksum
    unset CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN
    provider=$(jq -cn --arg script "$(realpath "${BASH_SOURCE[0]}")" '[$script]')
    # Cargo supplies the SHA-256 of the actual upload archive to this provider.
    cargo --config "registry.credential-provider=$provider" \
        publish --locked --registry crates-io -p "$package"
)
verify_repackaged_checksum
for ((attempt = 1; attempt <= 30; attempt++)); do
    checksum=$(registry_checksum)
    if [[ -n "$checksum" ]]; then
        verify_checksum "$checksum"
        echo "Published $package $version; archive checksum matches"
        exit 0
    fi
    if ((attempt < 30)); then sleep 10; fi
done
echo "$package $version not indexed after 30 checks; rerun after indexing completes" >&2
exit 1
