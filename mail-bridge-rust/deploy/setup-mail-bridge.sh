#!/bin/bash
# Run manually in a private SSH terminal: sudo bash /opt/mail-bridge-rust/setup-mail-bridge.sh
# This script does NOT connect to mail, start services, or enable SMTP/events.
set +x
set +v
set -euo pipefail
umask 077
export LC_ALL=C
[[ $EUID -eq 0 ]] || { printf 'Run with sudo bash.\n' >&2; exit 1; }
[[ -t 0 && -t 1 ]] || { printf 'An interactive private terminal is required.\n' >&2; exit 1; }
command -v jq >/dev/null
private=/etc/mail-bridge-rust
config=$private/config.json
[[ -d $private && ! -L $private && -f $config && ! -L $config ]] || exit 1
[[ ! -L $private/mailboxes ]] || exit 1
install -d -o root -g root -m 700 "$private/mailboxes"
temporary=''
cleanup() { unset secret confirmation owner_input; if [[ -n $temporary && $temporary == "$private/"* ]]; then rm -f -- "$temporary"; fi; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

printf 'Configuration only. SMTP and events remain OFF; service will not start.\n'
for account in qq zju; do
    file=$(jq -er --arg id "$account" '.accounts[]|select(.id==$id)|.password_file' "$config")
    [[ $file =~ ^[a-z0-9_-]{1,32}$ ]] || exit 1
    printf '\n%s full email address (Enter keeps current configuration): ' "$account"
    IFS= read -r address
    if [[ -n $address ]]; then
        [[ $address =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || { printf 'Invalid address.\n' >&2; exit 1; }
        [[ $account != qq || $address == *@qq.com ]] || { printf 'QQ address must end in @qq.com.\n' >&2; exit 1; }
        [[ $account != zju || $address == *@zju.edu.cn ]] || { printf 'ZJU address must end in @zju.edu.cn.\n' >&2; exit 1; }
        temporary=$(mktemp "$private/.config.XXXXXXXX")
        jq --arg id "$account" --arg address "$address" '.accounts |= map(if .id==$id then .config.username=$address|.config.from_address=$address else . end)|.accounts |= map(.config.smtp_enabled=false)' "$config" > "$temporary"
        chmod 600 "$temporary"
        chown root:root "$temporary"
        mv -f -- "$temporary" "$config"
        temporary=''
    fi
    target=$private/mailboxes/$file
    [[ ! -L $target ]] || { printf 'Credential symlinks are not supported.\n' >&2; exit 1; }
    if [[ -e $target ]]; then
        [[ -f $target && -s $target ]] || { printf 'Existing credential file is empty or invalid; inspect metadata yourself.\n' >&2; exit 1; }
        printf '%s credential already exists; kept without reading it.\n' "$account"
        continue
    fi
    printf '%s client authorization code/password (hidden; Enter skips): ' "$account"
    IFS= read -r -s secret
    printf '\n'
    if [[ -z $secret ]]; then unset secret; continue; fi
    [[ ${#secret} -le 1024 && $secret != *$'\r'* && $secret != *$'\n'* ]] || { printf 'Invalid credential length/characters.\n' >&2; exit 1; }
    printf 'Repeat the same credential (hidden): '
    IFS= read -r -s confirmation
    printf '\n'
    [[ $secret == "$confirmation" ]] || { printf 'Inputs differ; nothing written for this credential.\n' >&2; exit 1; }
    temporary=$(mktemp "$private/.credential.XXXXXXXX")
    # printf is a Bash builtin: the secret is never an external process argument.
    builtin printf '%s' "$secret" > "$temporary"
    chmod 600 "$temporary"
    chown root:root "$temporary"
    mv -n -- "$temporary" "$target"
    rm -f -- "$temporary"
    temporary=''
    unset secret confirmation
done
target=$private/owner_password
[[ ! -L $target ]] || exit 1
if [[ -e $target ]]; then
    [[ -f $target && -s $target ]] || { printf 'Existing owner file is empty or invalid.\n' >&2; exit 1; }
    printf '\nOwner password already exists; kept without reading it.\n'
else
    printf '\nEnter your own separate owner password, 32-256 ASCII characters (hidden): '
    IFS= read -r -s owner_input
    printf '\n'
    [[ ${#owner_input} -ge 32 && ${#owner_input} -le 256 && $owner_input != *[!\ -~]* ]] || { printf 'Owner password must be 32-256 printable ASCII characters.\n' >&2; exit 1; }
    printf 'Repeat owner password (hidden): '
    IFS= read -r -s confirmation
    printf '\n'
    [[ $owner_input == "$confirmation" ]] || { printf 'Inputs differ; owner file not written.\n' >&2; exit 1; }
    temporary=$(mktemp "$private/.credential.XXXXXXXX")
    builtin printf '%s' "$owner_input" > "$temporary"
    chmod 600 "$temporary"
    chown root:root "$temporary"
    mv -n -- "$temporary" "$target"
    rm -f -- "$temporary"
    temporary=''
    unset owner_input confirmation
fi
jq -e 'all(.accounts[];.config.smtp_enabled==false)' "$config" >/dev/null
[[ -f $private/safety.env && ! -L $private/safety.env ]] || exit 1
grep -qx 'MAIL_BRIDGE_EVENTS_ENABLED=false' "$private/safety.env"
printf '\nPrivate configuration saved. No service started, mailbox opened or email sent.\n'
printf 'When ready, you may run: sudo systemctl start mail-bridge-rust.service\n'
printf 'Do not paste secrets or the private state database into chat.\n'
