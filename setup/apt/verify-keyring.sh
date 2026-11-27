#!/bin/sh
# verify-keyring.sh KEYRING FINGERPRINT...
#
# Fails unless the primary key fingerprints in KEYRING are exactly the given
# ones, so a keyring that gains, loses or swaps a key fails the build.
set -eu
keyring="$1"
shift
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
have="$(gpg --show-keys --with-colons "$keyring" |
  awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }' |
  sort | tr '\n' ' ')"
rm -rf "$GNUPGHOME"
want="$(printf '%s\n' "$@" | sort | tr '\n' ' ')"
if [ "$have" != "$want" ]; then
  echo "$keyring has primary keys: $have" >&2
  echo "want: $want" >&2
  exit 1
fi
