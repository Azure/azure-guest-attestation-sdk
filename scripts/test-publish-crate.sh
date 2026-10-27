#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
mkdir -p "$work/bin" "$work/target/package"
cleanup() {
    rm -f "$work/bin/curl" "$work/bin/cargo" "$work/bin/sleep" \
        "$work/archive.crate" "$work/calls" "$work/uploaded" "$work/output" \
        "$work/target/package/azure-tpm-0.1.1.crate" \
        "$work/target/package/azure-guest-attestation-sdk-0.1.1.crate"
    rmdir "$work/bin" "$work/target/package" "$work/target" "$work"
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
run_case upload-mismatch failure 2 'repackaged archive checksum mismatch'
run_case publish-failure failure 2 'Publishing azure-tpm 0.1.1'
run_case timeout failure 2 'not indexed after 30 checks'

if bash "$root/scripts/publish-crate.sh" unexpected 0.1.1 "$MOCK_ARCHIVE" \
    > "$work/output" 2>&1; then
    echo "FAIL: unexpected package accepted" >&2
    exit 1
fi
echo 'All publish-crate tests passed.'
