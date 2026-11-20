#!/bin/sh
# Install the Agent Capsule workstation CLI from GitHub Releases.
#
#   curl -fsSL https://github.com/ArnaudGuiovanna/agentcapsule/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/ArnaudGuiovanna/agentcapsule/releases/latest/download/install.sh | sh -s -- --version v0.0.1
#
# The script picks the executable for this system (Linux or macOS, amd64 or
# arm64; Windows through Git Bash or MSYS2), downloads it with the release's
# SHA256SUMS, and installs it only if its digest is the one, single entry
# for that file. When cosign is on PATH, it first verifies that SHA256SUMS
# was signed by this repository's release workflow for that exact tag;
# --require-signature makes that check mandatory. See docs/release.md.
#
# Options (or environment variables):
#   --version TAG          AGENTCAPSULE_VERSION      release tag, default: the latest release
#   --dir DIR              AGENTCAPSULE_INSTALL_DIR  default: /usr/local/bin as root, else ~/.local/bin
#   --require-signature    AGENTCAPSULE_REQUIRE_SIGNATURE=1
#
# The whole script is a function called on its last line, so a truncated
# download runs nothing.

set -eu

REPOSITORY="ArnaudGuiovanna/agentcapsule"
ISSUER="https://token.actions.githubusercontent.com"

say() {
	printf 'agentcapsule-install: %s\n' "$*" >&2
}

die() {
	say "error: $*"
	exit 1
}

usage() {
	cat <<'EOF'
Install the Agent Capsule workstation CLI from GitHub Releases.

usage: install.sh [--version TAG] [--dir DIR] [--require-signature]

  --version TAG        release tag (AGENTCAPSULE_VERSION); default: the latest release
  --dir DIR            install directory (AGENTCAPSULE_INSTALL_DIR);
                       default: /usr/local/bin as root, else ~/.local/bin
  --require-signature  fail unless cosign verifies SHA256SUMS
                       (AGENTCAPSULE_REQUIRE_SIGNATURE=1)
EOF
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -- "$1" | cut -d ' ' -f 1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 -- "$1" | cut -d ' ' -f 1
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 -r "$1" | cut -d ' ' -f 1
	else
		die "sha256sum, shasum or openssl is required to verify the download"
	fi
}

download() {
	# download URL FILE
	curl --fail --silent --show-error --location --proto "$PROTOCOLS" --retry 3 \
		--output "$2" "$1" || die "download failed: $1"
}

main() {
	version="${AGENTCAPSULE_VERSION:-}"
	dir="${AGENTCAPSULE_INSTALL_DIR:-}"
	require_signature="${AGENTCAPSULE_REQUIRE_SIGNATURE:-0}"
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--version) [ "$#" -ge 2 ] || die "--version needs a tag"; version="$2"; shift 2 ;;
		--version=*) version="${1#--version=}"; shift ;;
		--dir) [ "$#" -ge 2 ] || die "--dir needs a directory"; dir="$2"; shift 2 ;;
		--dir=*) dir="${1#--dir=}"; shift ;;
		--require-signature) require_signature=1; shift ;;
		-h | --help) usage; exit 0 ;;
		*) die "unknown argument: $1 (see --help)" ;;
		esac
	done

	# AGENTCAPSULE_RELEASE_BASE_URL serves a mirror or a test fixture with
	# GitHub's layout: BASE/latest redirects to BASE/tag/TAG, and files are
	# at BASE/download/TAG/NAME. Only HTTPS is accepted for GitHub itself.
	base="${AGENTCAPSULE_RELEASE_BASE_URL:-https://github.com/$REPOSITORY/releases}"
	case "$base" in
	https://*) PROTOCOLS="=https" ;;
	http://127.0.0.1:* | http://localhost:*) PROTOCOLS="=http,https" ;;
	*) die "AGENTCAPSULE_RELEASE_BASE_URL must be an https:// URL" ;;
	esac
	command -v curl >/dev/null 2>&1 || die "curl is required"

	suffix=""
	case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	MINGW* | MSYS* | CYGWIN*) os=windows; suffix=".exe" ;;
	*) die "unsupported system $(uname -s): download the CLI from https://github.com/$REPOSITORY/releases" ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64 | ARM64) arch=arm64 ;;
	*) die "unsupported architecture $(uname -m): the CLI is built for amd64 and arm64" ;;
	esac
	# An x86_64 shell under Rosetta still runs on Apple silicon.
	if [ "$os" = darwin ] && [ "$arch" = amd64 ] &&
		[ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then
		arch=arm64
	fi
	asset="agentcapsule-$os-$arch$suffix"

	if [ -z "$version" ]; then
		latest="$(curl --fail --silent --show-error --location --proto "$PROTOCOLS" --retry 3 \
			--output /dev/null --write-out '%{url_effective}' "$base/latest")" ||
			die "cannot find the latest release at $base/latest"
		version="${latest##*/}"
	fi
	if ! printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
		die "not a release tag: '$version' (expected vMAJOR.MINOR.PATCH, such as v0.0.1)"
	fi

	if [ -z "$dir" ]; then
		if [ "$(id -u)" = 0 ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
	fi

	tmp="$(mktemp -d 2>/dev/null || mktemp -d -t agentcapsule-install)"
	trap 'rm -rf -- "$tmp"' EXIT
	trap 'exit 130' HUP INT TERM

	say "downloading $asset from release $version"
	url="$base/download/$version"
	download "$url/SHA256SUMS" "$tmp/SHA256SUMS"
	download "$url/$asset" "$tmp/$asset"

	if command -v cosign >/dev/null 2>&1; then
		download "$url/SHA256SUMS.sigstore.json" "$tmp/SHA256SUMS.sigstore.json"
		cosign verify-blob --bundle "$tmp/SHA256SUMS.sigstore.json" \
			--certificate-identity "https://github.com/$REPOSITORY/.github/workflows/release.yml@refs/tags/$version" \
			--certificate-oidc-issuer "$ISSUER" "$tmp/SHA256SUMS" </dev/null >&2 ||
			die "the signature of SHA256SUMS is not the release workflow's for $version"
		say "verified the signature of SHA256SUMS (release workflow, $version)"
	elif [ "$require_signature" = 1 ]; then
		die "--require-signature needs cosign 2.4 or newer on PATH"
	else
		say "cosign not found: checking the digest only. For the signature, see"
		say "https://github.com/$REPOSITORY/blob/main/docs/release.md#verify-a-release"
	fi

	expected="$(awk -v name="$asset" '$2 == name && NF == 2 { print $1 }' "$tmp/SHA256SUMS")"
	count="$(printf '%s' "$expected" | grep -c '' || true)"
	[ "$count" = 1 ] || die "SHA256SUMS of $version must list $asset exactly once (found $count)"
	printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$' || die "malformed SHA256SUMS entry for $asset"
	actual="$(sha256_of "$tmp/$asset")"
	[ "$actual" = "$expected" ] || die "checksum mismatch for $asset: expected $expected, got $actual"
	say "verified $asset ($actual)"

	mkdir -p -- "$dir" || die "cannot create $dir (choose another with --dir)"
	target="$dir/agentcapsule$suffix"
	cp -- "$tmp/$asset" "$dir/.agentcapsule-install.$$" || die "cannot write to $dir (choose another with --dir)"
	chmod 0755 "$dir/.agentcapsule-install.$$"
	mv -f -- "$dir/.agentcapsule-install.$$" "$target"
	say "installed $target"

	"$target" version </dev/null || die "$target does not run on this system"
	case ":${PATH:-}:" in
	*":$dir:"*) ;;
	*) say "add $dir to your PATH, for example: export PATH=\"$dir:\$PATH\"" ;;
	esac
	say "next: agentcapsule install --help (https://github.com/$REPOSITORY/blob/$version/docs/cli-host.md)"
}

main "$@"
