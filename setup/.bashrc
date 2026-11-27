# Load env vars from the env file safeclaw writes. Interactive shells don't
# read BASH_ENV, so the fixed path is sourced here.
[ -f /etc/safeclaw/env ] && . /etc/safeclaw/env

# Claude Code aliases
alias c='claude'
alias cs='claude --dangerously-skip-permissions'

# Claude --fs shortcut
claude() {
  local args=()
  for arg in "$@"; do
    if [[ "$arg" == "--fs" ]]; then
      args+=("--fork-session")
    else
      args+=("$arg")
    fi
  done
  command claude "${args[@]}"
}
