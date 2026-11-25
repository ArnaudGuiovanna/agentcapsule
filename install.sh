#!/bin/sh
# Install the Agent Capsule workstation CLI from GitHub Releases.
#
#   curl -fsSL https://github.com/ArnaudGuiovanna/agentcapsule/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/ArnaudGuiovanna/agentcapsule/releases/latest/download/install.sh | sh -s -- --version v0.0.1
#
# The script picks the executable for this system (Linux or macOS, amd64 or
# arm64; Windows through Git Bash or MSYS2), downloads it with the release's
# SHA256SUMS, and installs it only if its digest is the one, single entry
# for that file. First it verifies, with cosign and openssl, that SHA256SUMS
# was signed by this repository's release workflow for that exact tag, run by
# the push of the tag, in the protected release environment. When no cosign
# is on PATH it downloads the cosign release pinned below by SHA-256 and uses
# it for this run only. Without a verified cosign it stops, unless
# --insecure-skip-signature says to check the digest only. See docs/release.md.
#
# Options (or environment variables):
#   --version TAG               AGENTCAPSULE_VERSION      release tag, default: the latest release
#   --dir DIR                   AGENTCAPSULE_INSTALL_DIR  default: /usr/local/bin as root, else ~/.local/bin
#   --insecure-skip-signature   AGENTCAPSULE_INSECURE_SKIP_SIGNATURE=1
#   --require-signature         the default; kept for older instructions
#                               AGENTCAPSULE_COSIGN_BASE_URL  mirror of the pinned cosign release files
#
# The whole script is a function called on its last line, so a truncated
# download runs nothing.

set -eu

REPOSITORY="ArnaudGuiovanna/agentcapsule"
ISSUER="https://token.actions.githubusercontent.com"
# The signing run's deployment environment, in its certificate (S-16). The two
# releases signed before that environment existed are accepted by the digest
# of their SHA256SUMS; internal/hostops holds the same values.
ENVIRONMENT_OID="1.3.6.1.4.1.57264.1.23"
SIGNED_BEFORE_ENVIRONMENT="v0.0.1:500038470c97b46ea7efc31ca1fc08c305f46d2d181d61707a1c24e9ea30391e
v0.1.0:b0574da8b4811af9c57edc5127a58a68a09140c58391c2566a4815946f1a4c41"

# The cosign used when none is on PATH: the release files of this version,
# each accepted only with the SHA-256 that sigstore's signed
# cosign_checksums.txt gives it (the linux-amd64 pin of scripts/release-tools.json).
COSIGN_VERSION="v3.1.4"
COSIGN_SHA256="cosign-linux-amd64:424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
cosign-linux-arm64:ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2
cosign-darwin-amd64:9d1e4abe2b6be279ed0d2ff706fde1ccd738747c834e3e6d44039c238867334f
cosign-darwin-arm64:9f9b8cd557cf2e5b3df3373a00baa005a86b02391e3e06dd0ce37b3a1533d3a4
cosign-windows-amd64.exe:cbe953787074611f1334cbf37dc1cf953995bb8c45398eb4fc7bb781d29c1f2a"

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

usage: install.sh [--version TAG] [--dir DIR] [--insecure-skip-signature]

  --version TAG              release tag (AGENTCAPSULE_VERSION); default: the latest release
  --dir DIR                  install directory (AGENTCAPSULE_INSTALL_DIR);
                             default: /usr/local/bin as root, else ~/.local/bin
  --insecure-skip-signature  do not verify the signature of SHA256SUMS, only the
                             executable's digest (AGENTCAPSULE_INSECURE_SKIP_SIGNATURE=1).
                             Anyone who can change the release can change both.

The signature is verified by default, with openssl and cosign 2.4 or newer.
Without a cosign on PATH, the script downloads a pinned cosign release, checks
its SHA-256 and uses it for this run only. --require-signature, the default,
is still accepted.
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

pinned_cosign() {
	# pinned_cosign: download the pinned cosign for this system into the
	# temporary directory and name it in $cosign. Nothing but the pinned
	# bytes is ever run.
	cosign_asset="cosign-$os-$arch$suffix"
	cosign_pin="$(printf '%s\n' "$COSIGN_SHA256" | awk -F: -v name="$cosign_asset" '$1 == name { print $2 }')"
	[ -n "$cosign_pin" ] || die "cosign 2.4 or newer is required to verify the signature of SHA256SUMS,
  and this script pins no cosign for $os-$arch:
  https://docs.sigstore.dev/cosign/system_config/installation/
  (or pass --insecure-skip-signature to check the digest only; see
  https://github.com/$REPOSITORY/blob/main/docs/release.md#verify-a-release)"
	cosign_base="${AGENTCAPSULE_COSIGN_BASE_URL:-https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION}"
	case "$cosign_base" in
	https://* | http://127.0.0.1:* | http://localhost:*) ;;
	*) die "AGENTCAPSULE_COSIGN_BASE_URL must be an https:// URL" ;;
	esac
	say "no cosign on PATH: downloading cosign $COSIGN_VERSION to verify the signature"
	cosign="$tmp/cosign$suffix"
	download "$cosign_base/$cosign_asset" "$cosign"
	cosign_actual="$(sha256_of "$cosign")"
	[ "$cosign_actual" = "$cosign_pin" ] ||
		die "checksum mismatch for $cosign_asset $COSIGN_VERSION: expected $cosign_pin, got $cosign_actual"
	chmod 0700 "$cosign"
	"$cosign" version </dev/null >/dev/null 2>&1 ||
		die "the downloaded cosign does not run from $tmp (a noexec temporary directory?): set TMPDIR to another directory, or install cosign"
}

signing_environment() {
	# signing_environment BUNDLE: the deployment environment written in the
	# signing certificate of a Sigstore bundle, or nothing. openssl prints the
	# extension's DER bytes: ".." (UTF8String, length) then the name.
	certificate="$(tr -d '\n' <"$1" |
		sed -n 's/.*"certificate" *: *{ *"rawBytes" *: *"\([A-Za-z0-9+/=]*\)".*/\1/p')"
	[ -n "$certificate" ] || die "no signing certificate in SHA256SUMS.sigstore.json"
	printf '%s' "$certificate" | openssl base64 -d -A | openssl x509 -inform DER -noout -text |
		awk -v oid="$ENVIRONMENT_OID" '$1 == oid ":" { getline; sub(/^[ \t]+/, ""); sub(/[ \t]+$/, ""); print; exit }'
}

check_signing_environment() {
	# check_signing_environment BUNDLE SUMS: signed in the release environment.
	pin="$version:$(sha256_of "$2")"
	if printf '%s\n' "$SIGNED_BEFORE_ENVIRONMENT" | grep -Fqx -- "$pin"; then
		return 0
	fi
	command -v openssl >/dev/null 2>&1 || die "openssl is required to read the signing certificate"
	environment="$(signing_environment "$1")" || die "cannot read the signing certificate"
	[ "$environment" = "..release" ] ||
		die "SHA256SUMS of $version was not signed in the protected release environment"
}

main() {
	version="${AGENTCAPSULE_VERSION:-}"
	dir="${AGENTCAPSULE_INSTALL_DIR:-}"
	skip_signature="${AGENTCAPSULE_INSECURE_SKIP_SIGNATURE:-0}"
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--version) [ "$#" -ge 2 ] || die "--version needs a tag"; version="$2"; shift 2 ;;
		--version=*) version="${1#--version=}"; shift ;;
		--dir) [ "$#" -ge 2 ] || die "--dir needs a directory"; dir="$2"; shift 2 ;;
		--dir=*) dir="${1#--dir=}"; shift ;;
		--require-signature) shift ;;
		--insecure-skip-signature) skip_signature=1; shift ;;
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

	if [ "$skip_signature" = 1 ]; then
		say "WARNING: --insecure-skip-signature: the signature of SHA256SUMS is NOT verified."
		say "WARNING: the digest check below only proves that $asset matches SHA256SUMS;"
		say "WARNING: anyone who can replace the release files can replace both. Run this"
		say "WARNING: script again without --insecure-skip-signature."
	else
		if command -v cosign >/dev/null 2>&1; then cosign=cosign; else pinned_cosign; fi
		download "$url/SHA256SUMS.sigstore.json" "$tmp/SHA256SUMS.sigstore.json"
		"$cosign" verify-blob --bundle "$tmp/SHA256SUMS.sigstore.json" \
			--certificate-identity "https://github.com/$REPOSITORY/.github/workflows/release.yml@refs/tags/$version" \
			--certificate-oidc-issuer "$ISSUER" \
			--certificate-github-workflow-trigger push \
			--certificate-github-workflow-repository "$REPOSITORY" \
			--certificate-github-workflow-ref "refs/tags/$version" "$tmp/SHA256SUMS" </dev/null >&2 ||
			die "the signature of SHA256SUMS is not the release workflow's for $version"
		check_signing_environment "$tmp/SHA256SUMS.sigstore.json" "$tmp/SHA256SUMS"
		say "verified the signature of SHA256SUMS (release workflow, $version, release environment)"
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
