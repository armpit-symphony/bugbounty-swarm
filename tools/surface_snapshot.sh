#!/bin/sh
# surface_snapshot.sh — SparkPit Labs surface status snapshot
# POSIX shell, no bashisms.  Run on any surface to get a fast status dump.
#
# Usage:
#   bash tools/surface_snapshot.sh
#   bash tools/surface_snapshot.sh --json     # emit JSON line instead
#
# Set KEY_REPOS as space-separated paths to override defaults:
#   KEY_REPOS="/home/sparky/bugbounty-swarm /home/sparky/sparkpitlabs_handoff" bash tools/surface_snapshot.sh

set -eu

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SURFACE_NAME="${SURFACE_NAME:-$(hostname)}"
JSON_MODE=0

for arg in "$@"; do
    case "$arg" in
        --json) JSON_MODE=1 ;;
    esac
done

# Default key repos (override via KEY_REPOS env var)
DEFAULT_REPOS="
/home/sparky/.openclaw/workspace/bugbounty-swarm
/home/sparky/.openclaw/workspace/sparkpitlabs_handoff
/home/sparky/wepo
"
KEY_REPOS="${KEY_REPOS:-$DEFAULT_REPOS}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

_uptime_s() {
    if [ -r /proc/uptime ]; then
        cut -d' ' -f1 /proc/uptime | cut -d'.' -f1
    else
        echo "unknown"
    fi
}

_git_info() {
    repo="$1"
    if [ -d "$repo/.git" ]; then
        branch=$(git -C "$repo" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
        commit=$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo "unknown")
        dirty=$(git -C "$repo" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
        echo "$branch $commit dirty=$dirty"
    else
        echo "not-a-git-repo"
    fi
}

_services() {
    # Try docker compose, then systemctl, then ps fallback
    if command -v docker >/dev/null 2>&1; then
        docker ps --format "{{.Names}} {{.Status}}" 2>/dev/null | head -10 || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | \
            awk '{print $1, $4}' | head -10 || true
    fi
}

_cron_summary() {
    # Current user crontab
    crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | head -10 || echo "(no user crontab)"
    # System cron dirs
    for dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily; do
        if [ -d "$dir" ]; then
            files=$(ls "$dir" 2>/dev/null | tr '\n' ' ')
            [ -n "$files" ] && echo "$dir: $files"
        fi
    done
}

# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

if [ "$JSON_MODE" = "0" ]; then
    echo "============================================================"
    echo " SURFACE SNAPSHOT — $SURFACE_NAME"
    echo " $(date -u)"
    echo "============================================================"

    echo ""
    echo "--- SYSTEM ---"
    echo "Hostname : $(hostname)"
    echo "Uptime(s): $(_uptime_s)"
    uname -srm 2>/dev/null || true

    echo ""
    echo "--- KEY REPOS ---"
    for repo in $KEY_REPOS; do
        repo=$(echo "$repo" | tr -d '\n' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
        [ -z "$repo" ] && continue
        if [ -d "$repo" ]; then
            info=$(_git_info "$repo")
            echo "$repo  =>  $info"
        else
            echo "$repo  =>  NOT FOUND"
        fi
    done

    echo ""
    echo "--- RUNNING SERVICES ---"
    _services || echo "(could not enumerate services)"

    echo ""
    echo "--- CRON ---"
    _cron_summary

    echo ""
    echo "--- NETWORK LISTENERS ---"
    if command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | head -20 || true
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tlnp 2>/dev/null | head -20 || true
    else
        echo "(ss/netstat not available)"
    fi

    echo ""
    echo "============================================================"
    echo " END SNAPSHOT — $(_ts)"
    echo "============================================================"
    exit 0
fi

# ---------------------------------------------------------------------------
# JSON output (one-line JSONL for heartbeat_write.py consumption)
# ---------------------------------------------------------------------------

repos_json=""
sep=""
for repo in $KEY_REPOS; do
    repo=$(echo "$repo" | tr -d '\n' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
    [ -z "$repo" ] && continue
    if [ -d "$repo" ]; then
        info=$(_git_info "$repo")
        branch=$(echo "$info" | awk '{print $1}')
        commit=$(echo "$info" | awk '{print $2}')
        dirty=$(echo "$info" | awk '{print $3}' | cut -d= -f2)
        repos_json="${repos_json}${sep}{\"path\":\"$repo\",\"branch\":\"$branch\",\"commit\":\"$commit\",\"dirty_files\":$dirty}"
    else
        repos_json="${repos_json}${sep}{\"path\":\"$repo\",\"status\":\"not_found\"}"
    fi
    sep=","
done

uptime_s=$(_uptime_s)
ts=$(_ts)

printf '{"ts":"%s","surface":"%s","hostname":"%s","uptime_s":%s,"repos":[%s]}\n' \
    "$ts" "$SURFACE_NAME" "$(hostname)" "$uptime_s" "$repos_json"
