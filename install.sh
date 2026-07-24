#!/bin/sh
# Installs the latest vpsguard release for the current Linux host.
#
#   curl -fsSL https://raw.githubusercontent.com/salamancacm/vpsguard/main/install.sh | sh
#
# This is a trust-on-first-use install: you are running code from the
# network. The binary it fetches is verified against the SHA-256 checksums
# published alongside every release (see .github/workflows/release.yml),
# but the script itself is not. If you'd rather not pipe curl to sh, read
# this file, or download+verify the binary by hand per the README.
set -eu

REPO="salamancacm/vpsguard"
# Override for testing against a local mirror; real installs always use
# the default.
BASE_URL="${VPSGUARD_INSTALL_BASE_URL:-https://github.com/${REPO}/releases/latest/download}"

fail() {
	echo "error: $1" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "'$1' is required but not found on PATH"
}

require_cmd curl
require_cmd sha256sum
require_cmd mktemp

os="$(uname -s)"
if [ "$os" != "Linux" ]; then
	fail "vpsguard only runs on Linux (detected: $os)"
fi

arch="$(uname -m)"
case "$arch" in
x86_64 | amd64) arch="amd64" ;;
aarch64 | arm64) arch="arm64" ;;
*)
	fail "no prebuilt vpsguard binary for architecture '$arch' — build from source instead, see https://github.com/${REPO}#building-from-source"
	;;
esac

binary="vpsguard-linux-${arch}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "Downloading ${binary} (latest release)..."
curl -fsSL -o "${tmpdir}/${binary}" "${BASE_URL}/${binary}" ||
	fail "failed to download ${binary} from ${BASE_URL}"
curl -fsSL -o "${tmpdir}/checksums.txt" "${BASE_URL}/checksums.txt" ||
	fail "failed to download checksums.txt from ${BASE_URL}"

echo "Verifying checksum..."
expected="$(grep " ${binary}\$" "${tmpdir}/checksums.txt" | awk '{print $1}')"
[ -n "$expected" ] || fail "no checksum entry found for ${binary} in checksums.txt"

actual="$(sha256sum "${tmpdir}/${binary}" | awk '{print $1}')"
if [ "$expected" != "$actual" ]; then
	fail "checksum mismatch for ${binary}
  expected: ${expected}
  actual:   ${actual}
Refusing to install a binary that doesn't match its published checksum."
fi
echo "Checksum OK."

chmod +x "${tmpdir}/${binary}"

if [ "$(id -u)" = "0" ] || [ -w "/usr/local/bin" ]; then
	install_dir="/usr/local/bin"
else
	install_dir="${HOME}/.local/bin"
	mkdir -p "$install_dir"
fi

mv "${tmpdir}/${binary}" "${install_dir}/vpsguard"
echo "Installed vpsguard to ${install_dir}/vpsguard"

case ":${PATH}:" in
*":${install_dir}:"*) ;;
*)
	echo ""
	echo "Note: ${install_dir} is not on your PATH. Add it, e.g.:"
	echo "  export PATH=\"${install_dir}:\$PATH\""
	;;
esac

echo ""
"${install_dir}/vpsguard" --version
