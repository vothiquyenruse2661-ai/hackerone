#!/bin/bash
# run.sh — BBP Subdomain Monitor (GitHub Actions)
# Monitors subdomains across multiple accounts, diffs new vs old,
# scans new with nuclei, sends results to Discord.
set -eo pipefail

# ======================== CONFIG ========================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$REPO_ROOT/config/domains.txt"
DATA_DIR="$REPO_ROOT/data"
RESULTS_DIR="$REPO_ROOT/results"
FORCE_SCAN="${FORCE_SCAN:-false}"

# Subfinder settings
SUBFINDER_THREADS=100
CHAOS_API_KEY="${CHAOS_API_KEY:-}"

# Nuclei settings
NUCLEI_RATE_LIMIT=150
NUCLEI_CONCURRENCY=40
NUCLEI_FLAGS="-es info -etags ssl"

# ======================== LOGGING ========================
log()     { echo -e "\033[0;36m[$(date '+%H:%M:%S')]\033[0m $*"; }
log_ok()  { echo -e "\033[0;32m[$(date '+%H:%M:%S')] ✓\033[0m $*"; }
log_err() { echo -e "\033[0;31m[$(date '+%H:%M:%S')] ✗\033[0m $*"; }
log_warn(){ echo -e "\033[1;33m[$(date '+%H:%M:%S')] !\033[0m $*"; }

# ======================== CHECK TOOLS ========================
check_tools() {
    local missing=()
    for tool in subfinder httpx nuclei; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_err "Missing tools: ${missing[*]}"
        exit 1
    fi
    log_ok "All tools found"
}

# ======================== DISCORD ========================
send_discord() {
    local message="$1"
    local file="${2:-}"

    if [ -z "$DISCORD_WEBHOOK_URL" ]; then
        log_warn "DISCORD_WEBHOOK_URL not set — skipping notification"
        return 0
    fi

    if [ -n "$file" ] && [ -f "$file" ]; then
        curl -s -X POST "$DISCORD_WEBHOOK_URL" \
            -F "payload_json={\"content\":\"$message\"}" \
            -F "file=@$file" \
            --max-time 30 > /dev/null 2>&1 || log_warn "Discord file upload failed"
    else
        curl -s -X POST "$DISCORD_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"content\":\"$message\"}" \
            --max-time 30 > /dev/null 2>&1 || log_warn "Discord notification failed"
    fi
}

# ======================== PROCESS ONE ACCOUNT ========================
process_account() {
    local account="$1"
    shift
    local domains=("$@")

    local account_dir="$DATA_DIR/$account"
    local old_file="$account_dir/subdomains_old.txt"
    local new_file="$account_dir/subdomains_new.txt"
    local all_file="$account_dir/subdomains_all.txt"
    local httpx_file="$account_dir/httpx_live.txt"
    local nuclei_file="$account_dir/nuclei_results.txt"
    local results_file="$RESULTS_DIR/${account}_$(date +%F).txt"
    local first_run_marker="$account_dir/.first_run_done"

    mkdir -p "$account_dir" "$RESULTS_DIR"

    log "━━━ Account: $account (${#domains[@]} domains) ━━━"

    # ---- STEP 1: Subfinder Enum ----
    log "[$account] Running subfinder..."

    local domain_list
    domain_list=$(mktemp)
    printf '%s\n' "${domains[@]}" > "$domain_list"

    local subfinder_args=(
        -dL "$domain_list"
        -all
        -silent
        -t "$SUBFINDER_THREADS"
    )

    # Add Chaos API key if available
    if [ -n "$CHAOS_API_KEY" ]; then
        subfinder_args+=(-chaos-key "$CHAOS_API_KEY")
        log "[$account] Using Chaos API key"
    fi

    : > "$all_file"
    subfinder "${subfinder_args[@]}" 2>/dev/null | sort -u > "$all_file" || true
    rm -f "$domain_list"

    local total_subs
    total_subs=$(wc -l < "$all_file" | tr -d ' ')
    log_ok "[$account] Found $total_subs subdomains"

    if [ "$total_subs" -eq 0 ]; then
        log_warn "[$account] No subdomains found — skipping"
        echo "📁 $account: 0 subdomains found" >> "$RESULTS_DIR/summary.txt"
        return 0
    fi

    # ---- STEP 2: httpx Probe ----
    log "[$account] Probing with httpx..."

    : > "$httpx_file"
    httpx -l "$all_file" \
        -silent -nc \
        -t 80 \
        -rl 200 \
        -timeout 8 \
        -retries 1 \
        -o "$httpx_file" > /dev/null 2>&1 || true

    local live_count
    live_count=$(wc -l < "$httpx_file" | tr -d ' ')
    log_ok "[$account] Live hosts: $live_count"

    # ---- STEP 3: Diff (new vs old) ----
    : > "$new_file"

    if [ ! -f "$first_run_marker" ] || [ "$FORCE_SCAN" = "true" ]; then
        if [ ! -f "$first_run_marker" ]; then
            # FIRST RUN — baseline only, no scan
            log_warn "[$account] FIRST RUN — saving baseline only (no nuclei scan)"
            cp "$httpx_file" "$old_file" 2>/dev/null || true
            touch "$first_run_marker"

            echo "📁 **$account** — First run baseline" > "$results_file"
            echo "Total subs: $total_subs | Live: $live_count" >> "$results_file"
            echo "No scan performed (baseline established)" >> "$results_file"

            send_discord "📁 **$account** — Baseline established\nTotal: $total_subs | Live: $live_count\n_(No scan on first run)_" "$results_file"
            return 0
        fi
    fi

    # DIFF: find new subdomains
    if [ -f "$old_file" ] && [ -s "$old_file" ]; then
        # Compare live hosts against old baseline
        comm -23 <(sort -u "$httpx_file") <(sort -u "$old_file") > "$new_file" 2>/dev/null || true
    else
        # No old file — treat all as new
        cp "$httpx_file" "$new_file"
    fi

    local new_count
    new_count=$(wc -l < "$new_file" | tr -d ' ')
    log_ok "[$account] New subdomains: $new_count"

    # Update old file for next run
    cp "$httpx_file" "$old_file"

    # ---- STEP 4: Nuclei Scan (only if new subs exist) ----
    : > "$nuclei_file"

    if [ "$new_count" -gt 0 ]; then
        log "[$account] Running nuclei on $new_count new targets..."

        nuclei -l "$new_file" \
            $NUCLEI_FLAGS \
            -rl "$NUCLEI_RATE_LIMIT" \
            -c "$NUCLEI_CONCURRENCY" \
            -bs 50 \
            -silent -nc \
            -o "$nuclei_file" > /dev/null 2>&1 || true

        local findings
        findings=$(wc -l < "$nuclei_file" | tr -d ' ')
        log_ok "[$account] Nuclei findings: $findings"
    else
        log_ok "[$account] No new subdomains — skipping nuclei"
    fi

    # ---- STEP 5: Build Results File ----
    local findings_count
    findings_count=$(wc -l < "$nuclei_file" | tr -d ' ')

    cat > "$results_file" << EOF
═══════════════════════════════════════
  BBP Monitor Results — $(date +%F)
  Account: $account
═══════════════════════════════════════

📊 STATISTICS
  Total Subdomains:  $total_subs
  Live Hosts:        $live_count
  New Subdomains:    $new_count
  Nuclei Findings:   $findings_count

═══════════════════════════════════════

🆕 NEW SUBDOMAINS
EOF

    if [ "$new_count" -gt 0 ]; then
        cat "$new_file" >> "$results_file"
    else
        echo "  (none)" >> "$results_file"
    fi

    cat >> "$results_file" << EOF


═══════════════════════════════════════

🔍 NUCLEI FINDINGS
EOF

    if [ "$findings_count" -gt 0 ]; then
        cat "$nuclei_file" >> "$results_file"
    else
        echo "  (none)" >> "$results_file"
    fi

    echo "" >> "$results_file"

    # ---- STEP 6: Send to Discord ----
    local discord_msg="📁 **$account** — Scan Complete\n"
    discord_msg+="Total: $total_subs | Live: $live_count | New: $new_count | Findings: $findings_count"

    send_discord "$discord_msg" "$results_file"
}

# ======================== MAIN ========================
main() {
    echo ""
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║     BBP Subdomain Monitor             ║"
    echo "  ║     $(date +%F)                        ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo ""

    check_tools

    if [ ! -f "$CONFIG_FILE" ]; then
        log_err "Config file not found: $CONFIG_FILE"
        exit 1
    fi

    mkdir -p "$DATA_DIR" "$RESULTS_DIR"

    # Clear old summary
    : > "$RESULTS_DIR/summary.txt"

    # Read config and process each account
    local account_count=0
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        read -ra parts <<< "$line"
        local account="${parts[0]}"
        local domains=("${parts[@]:1}")

        if [ ${#domains[@]} -eq 0 ]; then
            log_warn "No domains for account '$account' — skipping"
            continue
        fi

        process_account "$account" "${domains[@]}" || true
        account_count=$((account_count + 1))

    done < "$CONFIG_FILE"

    # ---- Final Summary to Discord ----
    echo ""
    log "━━━ Monitor Complete ━━━"
    log "Accounts processed: $account_count"

    if [ -f "$RESULTS_DIR/summary.txt" ]; then
        log "Summary:"
        cat "$RESULTS_DIR/summary.txt"
    fi

    send_discord "✅ **BBP Monitor Complete** — $account_count accounts processed — $(date +%F)"
}

main "$@"
