#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
real_cargo=$(command -v cargo)
work=$(mktemp -d)
mkdir -p "$work/bin" "$work/target/package" "$work/cargo-home/registry"
cleanup() {
    rm -f "$work/bin/curl" "$work/bin/cargo" "$work/bin/sleep" \
        "$work/archive.crate" "$work/calls" "$work/uploaded" "$work/output" \
        "$work/credential" \
        "$work/cargo-home/registry/CACHEDIR.TAG" \
        "$work/target/package/azure-tpm-0.1.1.crate" \
        "$work/target/package/azure-guest-attestation-sdk-0.1.1.crate"
    rmdir "$work/bin" "$work/target/package" "$work/target" \
        "$work/cargo-home/registry" "$work/cargo-home" "$work"
}
trap cleanup EXIT

cat > "$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=
url=
while (($#)); do
    case "$1" in
        --output) output=$2; shift ;;
        https://*) url=$1 ;;
    esac
    shift
done
if [[ "$url" != "https://index.crates.io/az/ur/$MOCK_PACKAGE" ]]; then
    echo "unexpected registry URL: $url" >&2
    exit 1
fi
case "$MOCK_MODE" in
    network) exit 7 ;;
    http-error) printf 'forbidden' > "$output"; printf '403'; exit 0 ;;
    malformed) printf 'not JSON' > "$output"; printf '200'; exit 0 ;;
    empty) : > "$output"; printf '200'; exit 0 ;;
    invalid-record) printf '{"vers":"0.1.1","cksum":null,"yanked":false}\n' > "$output"; printf '200'; exit 0 ;;
    new-version)
        if [[ ! -f "$MOCK_UPLOADED" ]]; then
            jq -cn --arg checksum "$MOCK_CHECKSUM" \
                '{vers:"0.1.0",cksum:$checksum,yanked:false}' > "$output"
            printf '200'
            exit 0
        fi
        ;;
    publish|dry-run-mismatch|upload-mismatch|publish-failure|timeout)
        if [[ ! -f "$MOCK_UPLOADED" || "$MOCK_MODE" == timeout ]]; then
            : > "$output"
            printf '404'
            exit 0
        fi
        ;;
esac
checksum=$MOCK_CHECKSUM
yanked=false
if [[ "$MOCK_MODE" == mismatch ]]; then checksum=$(printf '%064d' 0); fi
if [[ "$MOCK_MODE" == yanked ]]; then yanked=true; fi
jq -cn --arg checksum "$checksum" --argjson yanked "$yanked" \
    '{vers:"0.1.1",cksum:$checksum,yanked:$yanked}' > "$output"
if [[ "$MOCK_MODE" == duplicate ]]; then
    jq -cn --arg checksum "$checksum" \
        '{vers:"0.1.1",cksum:$checksum,yanked:false}' >> "$output"
fi
printf '200'
EOF

cat > "$work/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_CALLS"
if [[ " $* " != *" --dry-run "* ]]; then
    [[ "${CARGO_REGISTRY_TOKEN+x}" != x ]]
    [[ "${CARGO_REGISTRIES_CRATES_IO_TOKEN+x}" != x ]]
    [[ "$1" == --config ]]
    provider=${2#registry.credential-provider=}
    [[ "$provider" != "$2" ]]
    mapfile -t command < <(jq -r '.[]' <<< "$provider")
    printf '%s\n' '{"v":1,"kind":"get","operation":"read","registry":{"index-url":"https://github.com/rust-lang/crates.io-index"}}' \
        | "${command[@]}" --cargo-plugin > "$MOCK_CREDENTIAL"
    tail -n 1 "$MOCK_CREDENTIAL" | jq -e '
        .Ok.token == "test-only-token" and .Ok.cache == "never"
        and .Ok.operation_independent == false' > /dev/null
fi
cp "$MOCK_ARCHIVE" "$CARGO_TARGET_DIR/package/$MOCK_PACKAGE-0.1.1.crate"
if [[ " $* " == *" --dry-run "* ]]; then
    if [[ "$MOCK_MODE" == dry-run-mismatch ]]; then
        printf 'changed' >> "$CARGO_TARGET_DIR/package/$MOCK_PACKAGE-0.1.1.crate"
    fi
else
    if [[ "$MOCK_MODE" == publish-failure ]]; then exit 101; fi
    if [[ "$MOCK_MODE" == upload-mismatch ]]; then
        printf 'changed' >> "$CARGO_TARGET_DIR/package/$MOCK_PACKAGE-0.1.1.crate"
    fi
    checksum=$(sha256sum "$CARGO_TARGET_DIR/package/$MOCK_PACKAGE-0.1.1.crate")
    jq -cn --arg name "$MOCK_PACKAGE" --arg checksum "${checksum%% *}" \
        '{v:1,kind:"get",operation:"publish",name:$name,vers:"0.1.1",cksum:$checksum,
          registry:{"index-url":"https://github.com/rust-lang/crates.io-index"}}' \
        | "${command[@]}" --cargo-plugin > "$MOCK_CREDENTIAL"
    tail -n 1 "$MOCK_CREDENTIAL" | jq -e '
        .Ok.token == "test-only-token" and .Ok.cache == "never"
        and .Ok.operation_independent == false' > /dev/null
    : > "$MOCK_UPLOADED"
fi
EOF

cat > "$work/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$work/bin/curl" "$work/bin/cargo" "$work/bin/sleep"

export PATH="$work/bin:$PATH"
export CARGO_TARGET_DIR="$work/target"
export MOCK_ARCHIVE="$work/archive.crate"
export MOCK_CALLS="$work/calls"
export MOCK_UPLOADED="$work/uploaded"
export MOCK_CREDENTIAL="$work/credential"
export CARGO_REGISTRY_TOKEN=test-only-token
export CARGO_REGISTRIES_CRATES_IO_TOKEN=must-not-bypass-provider
printf 'verified archive\n' > "$MOCK_ARCHIVE"
MOCK_CHECKSUM=$(sha256sum "$MOCK_ARCHIVE")
export MOCK_CHECKSUM=${MOCK_CHECKSUM%% *}

run_case() {
    local mode=$1 expected=$2 expected_calls=$3 message=$4 result=0 calls
    export MOCK_MODE=$mode
    export MOCK_PACKAGE=${5:-azure-tpm}
    : > "$MOCK_CALLS"
    rm -f "$MOCK_UPLOADED"
    bash "$root/scripts/publish-crate.sh" "$MOCK_PACKAGE" 0.1.1 "$MOCK_ARCHIVE" \
        > "$work/output" 2>&1 || result=$?
    if [[ "$expected" == success && "$result" != 0 ]] ||
        [[ "$expected" == failure && "$result" == 0 ]]; then
        cat "$work/output" >&2
        echo "FAIL: $mode returned $result" >&2
        exit 1
    fi
    calls=$(wc -l < "$MOCK_CALLS")
    if [[ "$calls" -ne "$expected_calls" ]]; then
        echo "FAIL: $mode invoked Cargo $calls times, expected $expected_calls" >&2
        exit 1
    fi
    if ! grep -Fq "$message" "$work/output"; then
        cat "$work/output" >&2
        echo "FAIL: $mode did not report $message" >&2
        exit 1
    fi
    if [[ "$expected" == failure && "${6:-}" != uploaded && -f "$MOCK_UPLOADED" ]]; then
        echo "FAIL: $mode uploaded an archive before failing" >&2
        exit 1
    fi
    echo "PASS: $mode"
}

run_case existing success 0 'Already published'
run_case publish success 2 'archive checksum matches'
run_case publish success 2 'archive checksum matches' azure-guest-attestation-sdk
run_case new-version success 2 'archive checksum matches'
run_case mismatch failure 0 'registry archive checksum mismatch'
run_case yanked failure 0 'release version is yanked'
run_case network failure 0 'registry request failed'
run_case http-error failure 0 'registry returned HTTP 403'
run_case malformed failure 0 'parse error'
run_case empty failure 0 'empty registry index'
run_case duplicate failure 0 'duplicate registry version'
run_case invalid-record failure 0 'missing registry checksum'
run_case dry-run-mismatch failure 1 'repackaged archive checksum mismatch'
run_case upload-mismatch failure 2 'upload authorization rejected'
run_case publish-failure failure 2 'Publishing azure-tpm 0.1.1'
run_case timeout failure 2 'not indexed after 30 checks' azure-tpm uploaded

export RELEASE_PUBLISH_TOKEN=test-only-token
export RELEASE_PUBLISH_PACKAGE=azure-tpm RELEASE_PUBLISH_VERSION=0.1.1
export RELEASE_PUBLISH_CHECKSUM=$MOCK_CHECKSUM
request=$(jq -cn --arg checksum "$MOCK_CHECKSUM" '
    {v:1,kind:"get",operation:"publish",name:"azure-tpm",vers:"0.1.1",
     cksum:$checksum,registry:{"index-url":"sparse+https://index.crates.io/"}}')
printf '%s\n' "$request" | bash "$root/scripts/publish-crate.sh" --cargo-plugin \
    > "$MOCK_CREDENTIAL"
tail -n 1 "$MOCK_CREDENTIAL" | jq -e '
    .Ok.token == "test-only-token" and .Ok.cache == "never"
    and .Ok.operation_independent == false' > /dev/null

for change in '.v = 2' '.kind = "login"' '.operation = "yank"' \
    '.registry["index-url"] = "https://unexpected.invalid/"' \
    '.name = "unexpected"' '.vers = "0.2.0"' '.cksum = null' \
    '.cksum = "wrong"' 'del(.cksum)'; do
    if jq -c "$change" <<< "$request" \
        | bash "$root/scripts/publish-crate.sh" --cargo-plugin \
            > "$MOCK_CREDENTIAL" 2> "$work/output"; then
        echo "FAIL: credential provider accepted $change" >&2
        exit 1
    fi
    if grep -Fq test-only-token "$MOCK_CREDENTIAL"; then
        echo "FAIL: rejected request received credentials" >&2
        exit 1
    fi
done
if printf '%s\n' "$request" | RELEASE_PUBLISH_TOKEN='' \
    bash "$root/scripts/publish-crate.sh" --cargo-plugin \
        > "$MOCK_CREDENTIAL" 2> "$work/output"; then
    echo "FAIL: credential provider accepted missing token" >&2
    exit 1
fi
echo 'PASS: credential provider validation and non-cacheable authorization'

provider=$(jq -cn --arg script "$root/scripts/publish-crate.sh" '[$script]')
if CARGO_HOME="$work/cargo-home" "$real_cargo" \
    --config "registry.credential-provider=$provider" logout --registry crates-io \
        > "$work/output" 2>&1; then
    echo "FAIL: real Cargo unexpectedly accepted logout" >&2
    exit 1
fi
if ! grep -Fq 'upload authorization rejected' "$work/output"; then
    cat "$work/output" >&2
    echo "FAIL: real Cargo did not invoke the credential provider" >&2
    exit 1
fi
echo 'PASS: real Cargo credential-provider protocol'

if bash "$root/scripts/publish-crate.sh" unexpected 0.1.1 "$MOCK_ARCHIVE" \
    > "$work/output" 2>&1; then
    echo "FAIL: unexpected package accepted" >&2
    exit 1
fi
echo 'All publish-crate tests passed.'
