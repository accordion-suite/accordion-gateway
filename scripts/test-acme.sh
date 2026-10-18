#!/usr/bin/env bash
# Runs the ACME tests against Pebble, Let's Encrypt's test certificate
# authority, so they never touch the real Let's Encrypt.
#
# Usage: scripts/test-acme.sh
#
# Downloads a pinned Pebble release into target/pebble the first time, checks
# its checksums, starts Pebble and its test DNS server, and runs the tests
# marked "needs Pebble". CI runs this too.

set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
dir="$repo/target/pebble"
version="v2.10.1"
release="https://github.com/letsencrypt/pebble/releases/download/$version"
source="https://raw.githubusercontent.com/letsencrypt/pebble/$version"

case "$(uname -m)" in
    x86_64)
        arch=amd64
        pebble_sha=4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed
        challtestsrv_sha=e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92
        ;;
    aarch64)
        arch=arm64
        pebble_sha=b53fd072a69eb7692451de4e8b0667e0bdf5cccd7e36fc51b8eaf2fcc135ed9f
        challtestsrv_sha=db8e1a79ccdb2195c489fbe4f40fddb7f30e86f9cd8a07912566ee5025094d6c
        ;;
    *)
        echo "Pebble has no Linux release for $(uname -m)." >&2
        exit 1
        ;;
esac

# Downloads $1 to $2 unless it's already there, and stops if its SHA-256
# isn't $3.
fetch() {
    local url="$1" path="$2" sha="$3"
    if [[ ! -f "$path" ]]; then
        mkdir -p "$(dirname "$path")"
        curl -fsSL "$url" -o "$path.part"
        mv "$path.part" "$path"
    fi
    if ! echo "$sha  $path" | sha256sum --check --quiet; then
        echo "$path doesn't match its pinned checksum. Delete $dir and try again." >&2
        exit 1
    fi
}

for program in pebble pebble-challtestsrv; do
    sha_var="${program//-/_}_sha"
    sha_var="${sha_var/pebble_challtestsrv/challtestsrv}"
    archive="$dir/downloads/$program-linux-$arch.tar.gz"
    fetch "$release/$program-linux-$arch.tar.gz" "$archive" "${!sha_var}"
    if [[ ! -x "$dir/bin/$program" ]]; then
        mkdir -p "$dir/bin"
        tar -xzf "$archive" -C "$dir/downloads"
        mv "$dir/downloads/$program-linux-$arch/linux/$arch/$program" "$dir/bin/$program"
        # The release archives don't keep the executable bit.
        chmod +x "$dir/bin/$program"
    fi
done

# Pebble's config and the certificate for its own HTTPS server. Its config
# refers to the certificate by this relative path.
fetch "$source/test/config/pebble-config.json" "$dir/test/config/pebble-config.json" \
    735f32ae7ff73cc9ac6c4505c0387f0773f16776f5f71fcd9886c413ae5b702e
fetch "$source/test/certs/localhost/cert.pem" "$dir/test/certs/localhost/cert.pem" \
    c87fb918d9bac8db11aa54493b5f0cf6e0725a3fe73f617d1c64737e1ab4caf9
fetch "$source/test/certs/localhost/key.pem" "$dir/test/certs/localhost/key.pem" \
    0977979255b0e0721c17335c056b627f66a43cf56e5a52f3cda81fb111ecf00e
fetch "$source/test/certs/pebble.minica.pem" "$dir/test/certs/pebble.minica.pem" \
    0c502e52627ff7de972c7e9e065640103b4589b4e2d23d3fcf21bef1e3c8c67c

pids=()
trap 'kill "${pids[@]}" 2> /dev/null || true' EXIT

# Only the DNS server and its management API. The other challenge servers
# aren't needed and would take more ports.
"$dir/bin/pebble-challtestsrv" -dnsserver 127.0.0.1:8053 -management 127.0.0.1:8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" > "$dir/challtestsrv.log" 2>&1 &
pids+=($!)

# No artificial delays, and no random nonce rejections, so the tests are
# quick and repeatable.
(cd "$dir" && PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 \
    exec "$dir/bin/pebble" -config test/config/pebble-config.json -dnsserver 127.0.0.1:8053) \
    > "$dir/pebble.log" 2>&1 &
pids+=($!)

ready=false
for _ in $(seq 50); do
    if curl -fs --cacert "$dir/test/certs/pebble.minica.pem" https://localhost:14000/dir > /dev/null; then
        ready=true
        break
    fi
    sleep 0.2
done
if [[ "$ready" != true ]]; then
    echo "Pebble didn't start. Its logs are in $dir/pebble.log and $dir/challtestsrv.log." >&2
    exit 1
fi

cd "$repo"
PEBBLE_ROOT="$dir/test/certs/pebble.minica.pem" cargo test --locked --test acme -- --ignored
