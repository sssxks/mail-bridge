#!/usr/bin/env bash
# Upgrade an already migrated runtime-account installation; run with sudo.
# Usage: bash upgrade-mail-bridge.sh STAGE SHA256 PUBLIC_ORIGIN
set -eEuo pipefail
umask 077
[[ $EUID -eq 0 ]]
stage=$(realpath -- "$1")
expected=$2
origin=$3
live=/opt/mail-bridge-rust/mail-bridge-rust
state=$(readlink -f /var/lib/mail-bridge-rust)
[[ $state == /var/lib/private/mail-bridge-rust ]]
[[ $(sha256sum "$stage/mail-bridge-rust" | cut -d ' ' -f1) == "$expected" ]]
systemctl is-active --quiet mail-bridge-rust
backup=/var/backups/mail-bridge-rust/$(date -u +%Y%m%dT%H%M%SZ)-binary-upgrade
install -d -m 700 "$backup"
cp -a "$live" "$backup/binary"
cp -a /etc/mail-bridge-rust "$backup/private"
rollback() {
    trap - ERR
    systemctl stop mail-bridge-rust || true
    cp -a "$backup/binary" "$live"
    cp -a "$backup/private/." /etc/mail-bridge-rust/
    # Keep the current database: never discard newer OAuth or send records.
    systemctl start mail-bridge-rust
    printf 'Upgrade failed; binary/config restored from %s\n' "$backup" >&2
    exit 1
}
trap rollback ERR
systemctl stop mail-bridge-rust
cp -a "$state" "$backup/state"
install -m 755 "$stage/mail-bridge-rust" "$live.next"
mv -f "$live.next" "$live"
systemctl start mail-bridge-rust
for attempt in 1 2 3 4 5; do
    if curl --fail --silent http://127.0.0.1:18765/.well-known/oauth-protected-resource >/dev/null; then break; fi
    sleep 1
done
python3 "$stage/verify-mail-bridge-upgrade.py" "$state/mail-bridge.sqlite3" "$backup/state/mail-bridge.sqlite3" "$origin"
systemctl is-active --quiet mail-bridge-rust
trap - ERR
systemctl show mail-bridge-rust -p ActiveState -p NRestarts --no-pager
sha256sum "$live"
printf 'Backup: %s\n' "$backup"
