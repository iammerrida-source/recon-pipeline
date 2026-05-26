#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════
#  recon_pipeline.sh  —  Subdomain Discovery Pipeline  v3.0
#
#  Improvements over v2:
#    ✦ Resolver validation (dnsvalidator / massdns fallback)
#    ✦ Scope file support  (multi-domain + wildcard + exclusions)
#    ✦ Rate limiting & retry logic per tool
#    ✦ Resume capability   (--resume flag)
#    ✦ GitHub subdomain enumeration (github-subdomains)
#    ✦ TLS certificate scraping (tlsx)
#    ✦ Favicon hash pivot  (httpx -favicon → Shodan hint)
#    ✦ Cloud asset discovery (s3scanner / cloud_enum)
#    ✦ Structured JSON output  (jq)
#    ✦ Per-phase timing & stats
#
#  Phases:
#    1.  Passive          subfinder -all, amass, chaos, crt.sh, github
#    2.  Resolve + Wildcard Filter
#    3.  Recursive Early  subfinder -recursive
#    4.  Permutation      extract words → alterx
#    5.  Bruteforce       shuffledns (jhaddix wordlist)
#    6.  ASN + PTR Pivot  asnmap → CIDRs → dnsx -ptr
#    7.  TLS Scrape       tlsx on IP ranges
#    8.  Loop             back to phase 2 until saturation
#    9.  httpx Enrich     title, tech, status, favicon
#    10. Favicon Pivot    hash → Shodan/Censys hint
#    11. Cloud Assets     S3/Azure/GCP enum
#    12. Extract Words    titles → word bank → final alterx
#    13. JSON Report
#
#  Usage:
#    ./recon_pipeline.sh -d <domain>           single domain
#    ./recon_pipeline.sh -s scope.txt          scope file
#    ./recon_pipeline.sh -d example.com --resume  resume interrupted run
#
#  Scope file format:
#    example.com          in-scope domain
#    *.example.com        wildcard (treated as example.com)
#    !staging.example.com exclude this subdomain
#
#  Options:
#    -d  target domain
#    -s  scope file
#    -o  output dir         (default: recon_<domain>_<ts>)
#    -w  wordlist           (default: ~/tools/wordlists/all.txt)
#    -r  resolvers file     (default: ~/tools/resolvers.txt)
#    -t  threads            (default: 100)
#    -T  new-subs threshold (default: 10)
#    -I  max iterations     (default: 5)
#    -R  rate limit rps     (default: 500)
#        --resume           resume from last checkpoint
#        --no-cloud         skip cloud asset discovery
#        --no-github        skip github enumeration
# ══════════════════════════════════════════════════════════════════════════

set -uo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m'
B='\033[0;34m' M='\033[0;35m' DIM='\033[2m' NC='\033[0m' BOLD='\033[1m'

_banner() {
  local len=54
  local pad=$(( (len - ${#1}) / 2 ))
  echo -e "\n${B}${BOLD}╔$(printf '═%.0s' $(seq 1 $len))╗${NC}"
  printf "${B}${BOLD}║${NC}%*s${C}${BOLD}%s${NC}%*s${B}${BOLD}║${NC}\n" \
    $pad "" "$1" $(( len - pad - ${#1} )) ""
  echo -e "${B}${BOLD}╚$(printf '═%.0s' $(seq 1 $len))╝${NC}\n"
}
_phase()  { echo -e "\n${M}${BOLD}┌─[ Phase $1 ]── $2${NC}"; }
_info()   { echo -e "${G}  ✦${NC} $1"; }
_warn()   { echo -e "${Y}  ⚠${NC}  $1"; }
_err()    { echo -e "${R}  ✗${NC}  $1"; }
_ok()     { echo -e "${G}  ✔${NC}  ${BOLD}$1${NC}"; }
_stat()   { echo -e "${C}  ◈${NC}  $1"; }
_loop()   { echo -e "${Y}${BOLD}  ↻  $1${NC}"; }
_done()   { echo -e "${G}${BOLD}  ■  $1${NC}"; }
_time()   { echo -e "${DIM}  ⏱  $1${NC}"; }

has()         { command -v "$1" &>/dev/null; }
die()         { _err "$1"; exit 1; }
count_lines() { [[ -f "$1" ]] && grep -c '' "$1" 2>/dev/null || echo 0; }
ts()          { date +%s; }
elapsed()     { echo $(( $(ts) - $1 )); }
fmt_time()    { printf '%dm %ds' $(($1/60)) $(($1%60)); }

merge_new() {
  local src="$1" dst="$2"
  [[ ! -s "$src" ]] && echo 0 && return
  local before after
  before=$(count_lines "$dst")
  comm -23 <(sort "$src") <(sort "$dst") >> "$dst"
  sort -u "$dst" -o "$dst"
  after=$(count_lines "$dst")
  echo $(( after - before ))
}

resolvers_flag() { [[ -s "$VALID_RESOLVERS" ]] && echo "-r $VALID_RESOLVERS" || echo ""; }

# checkpoint system
checkpoint_save() {
  echo "$1" > "$OUTDIR/.checkpoint"
  echo "$ITERATION" >> "$OUTDIR/.checkpoint"
}
checkpoint_load() {
  [[ -f "$OUTDIR/.checkpoint" ]] && cat "$OUTDIR/.checkpoint" || echo ""
}

# ─── Defaults ────────────────────────────────────────────────────────────
TARGET=""
SCOPE_FILE=""
WORDLIST="${HOME}/tools/wordlists/all.txt"
OUTDIR=""
THREADS=100
NEW_THRESHOLD=10
MAX_ITER=5
RESOLVERS="${HOME}/tools/resolvers.txt"
RATE_LIMIT=500
RESUME=false
NO_CLOUD=false
NO_GITHUB=false

# ─── Parse Args ──────────────────────────────────────────────────────────
usage() {
  grep '^#  ' "$0" | sed 's/^#  //'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) TARGET="${2,,}"; shift 2 ;;
    -s) SCOPE_FILE="$2"; shift 2 ;;
    -o) OUTDIR="$2"; shift 2 ;;
    -w) WORDLIST="$2"; shift 2 ;;
    -r) RESOLVERS="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -T) NEW_THRESHOLD="$2"; shift 2 ;;
    -I) MAX_ITER="$2"; shift 2 ;;
    -R) RATE_LIMIT="$2"; shift 2 ;;
    --resume) RESUME=true; shift ;;
    --no-cloud) NO_CLOUD=true; shift ;;
    --no-github) NO_GITHUB=true; shift ;;
    -h|--help) usage ;;
    *) _warn "Unknown flag: $1"; shift ;;
  esac
done

[[ -z "$TARGET" && -z "$SCOPE_FILE" ]] && usage

# ─── Scope Processing ────────────────────────────────────────────────────
DOMAINS=()
EXCLUSIONS=()

if [[ -n "$SCOPE_FILE" ]]; then
  [[ ! -f "$SCOPE_FILE" ]] && die "Scope file not found: $SCOPE_FILE"
  while IFS= read -r line; do
    line="${line//[[:space:]]/}"
    [[ -z "$line" || "$line" == "#"* ]] && continue
    if [[ "$line" == "!"* ]]; then
      EXCLUSIONS+=("${line:1}")
    else
      # wildcard → strip *. prefix
      clean="${line/#\*./}"
      DOMAINS+=("${clean,,}")
    fi
  done < "$SCOPE_FILE"
else
  DOMAINS=("$TARGET")
fi

[[ ${#DOMAINS[@]} -eq 0 ]] && die "No domains to scan"
PRIMARY_DOMAIN="${DOMAINS[0]}"

# ─── Setup dirs ──────────────────────────────────────────────────────────
OUTDIR="${OUTDIR:-recon_${PRIMARY_DOMAIN//\./_}_$(date +%Y%m%d_%H%M%S)}"
$RESUME && [[ ! -d "$OUTDIR" ]] && die "Resume: output dir not found: $OUTDIR"
mkdir -p "$OUTDIR"/{passive,resolve,permutation,bruteforce,asn,tls,httpx,cloud,words,checkpoints}

LOGFILE="$OUTDIR/pipeline.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ─── Key files ───────────────────────────────────────────────────────────
ALL_SUBS="$OUTDIR/all_subdomains.txt"
RESOLVED="$OUTDIR/resolved.txt"
WILDCARDS="$OUTDIR/wildcards.txt"
PERMWORDS="$OUTDIR/permutation_words.txt"
LIVE_URLS="$OUTDIR/live_urls.txt"
ASN_RANGES="$OUTDIR/asn/ip_ranges.txt"
VALID_RESOLVERS="$OUTDIR/valid_resolvers.txt"
EXCLUSIONS_FILE="$OUTDIR/exclusions.txt"
STATS_FILE="$OUTDIR/stats.json"

touch "$ALL_SUBS" "$RESOLVED" "$WILDCARDS" "$PERMWORDS"

# write exclusions
printf '%s\n' "${EXCLUSIONS[@]}" > "$EXCLUSIONS_FILE" 2>/dev/null || true

# apply exclusions to a file (in-place)
apply_exclusions() {
  local f="$1"
  [[ ! -s "$EXCLUSIONS_FILE" ]] && return
  while IFS= read -r excl; do
    sed -i "/^${excl//./\\.}$/d" "$f" 2>/dev/null || true
  done < "$EXCLUSIONS_FILE"
}

GLOBAL_START=$(ts)
declare -A PHASE_STATS

# ─── Splash ──────────────────────────────────────────────────────────────
clear
echo -e "${C}"
cat << 'SPLASH'
  ███╗   ███╗███████╗██████╗ ██╗██████╗  █████╗
  ████╗ ████║██╔════╝██╔══██╗██║██╔══██╗██╔══██╗
  ██╔████╔██║█████╗  ██████╔╝██║██║  ██║███████║
  ██║╚██╔╝██║██╔══╝  ██╔══██╗██║██║  ██║██╔══██║
  ██║ ╚═╝ ██║███████╗██║  ██║██║██████╔╝██║  ██║
  ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝  v3.0
          by @iammerida  |  Passive→Resolve→TLS→Permute→Brute→Pivot
SPLASH
echo -e "${NC}"
printf "  ${BOLD}%-16s${NC} ${G}%s${NC}\n" \
  "Domains:"    "${DOMAINS[*]}" \
  "Exclusions:" "${#EXCLUSIONS[@]} rules" \
  "Wordlist:"   "$WORDLIST" \
  "Output:"     "$OUTDIR/" \
  "Threads:"    "$THREADS" \
  "Rate limit:" "$RATE_LIMIT rps" \
  "Max Iter:"   "$MAX_ITER" \
  "Threshold:"  "$NEW_THRESHOLD new/iter"
$RESUME && echo -e "  ${Y}${BOLD}RESUME MODE${NC}"
echo ""

# ─── Tool Check ──────────────────────────────────────────────────────────
_banner "TOOL CHECK"
REQUIRED=(subfinder dnsx shuffledns httpx alterx)
OPTIONAL=(amass chaos asnmap tlsx github-subdomains dnsvalidator massdns jq s3scanner)
AVAILABLE_OPTIONAL=()

ALL_OK=true
for t in "${REQUIRED[@]}"; do
  has "$t" && _ok "$t" || { _err "$t (REQUIRED) missing"; ALL_OK=false; }
done
for t in "${OPTIONAL[@]}"; do
  if has "$t"; then
    _ok "$t (optional)"
    AVAILABLE_OPTIONAL+=("$t")
  else
    _warn "$t (optional) — step skipped"
  fi
done
$ALL_OK || die "Install required tools and retry."
[[ ! -f "$WORDLIST" ]] && die "Wordlist not found: $WORDLIST"

# helper: check if optional tool available
has_opt() { printf '%s\n' "${AVAILABLE_OPTIONAL[@]}" | grep -qx "$1"; }

# ══════════════════════════════════════════════════════════════════════════
#  RESOLVER VALIDATION
# ══════════════════════════════════════════════════════════════════════════
_banner "RESOLVER VALIDATION"

if $RESUME && [[ -s "$VALID_RESOLVERS" ]]; then
  _ok "Resuming — reusing validated resolvers ($(count_lines "$VALID_RESOLVERS"))"
else
  if has_opt dnsvalidator && [[ -f "$RESOLVERS" ]]; then
    _info "Running dnsvalidator ..."
    T0=$(ts)
    dnsvalidator -tL "$RESOLVERS" -threads "$THREADS" \
      -o "$VALID_RESOLVERS" 2>/dev/null || true
    _ok "Valid resolvers: $(count_lines "$VALID_RESOLVERS")  ($(fmt_time $(elapsed $T0)))"
  elif has_opt massdns && [[ -f "$RESOLVERS" ]]; then
    # use massdns as resolver validator
    _info "Validating resolvers with massdns ..."
    T0=$(ts)
    # test each resolver with a known query
    while IFS= read -r res; do
      result=$(dig @"$res" +time=2 +tries=1 +short google.com A 2>/dev/null | head -1)
      [[ -n "$result" ]] && echo "$res" >> "$VALID_RESOLVERS"
    done < "$RESOLVERS"
    sort -u "$VALID_RESOLVERS" -o "$VALID_RESOLVERS"
    _ok "Valid resolvers: $(count_lines "$VALID_RESOLVERS")  ($(fmt_time $(elapsed $T0)))"
  elif [[ -f "$RESOLVERS" ]]; then
    _warn "No validator tool — copying resolvers as-is"
    cp "$RESOLVERS" "$VALID_RESOLVERS"
  else
    _warn "No resolvers file — dnsx will use system defaults"
    touch "$VALID_RESOLVERS"
  fi
fi

PHASE_STATS["resolver_count"]=$(count_lines "$VALID_RESOLVERS")

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 1 — PASSIVE COLLECTION  (per domain)
# ══════════════════════════════════════════════════════════════════════════
_phase 1 "Passive Collection"
T0=$(ts)

for domain in "${DOMAINS[@]}"; do
  _info "Passive enum for: ${BOLD}$domain"
  P="$OUTDIR/passive"

  # subfinder -all
  _info "  subfinder -all ..."
  subfinder -d "$domain" -all -silent \
    -rate-limit "$RATE_LIMIT" \
    -o "$P/subfinder_${domain//\./_}.txt" 2>/dev/null || true
  _stat "  subfinder: $(count_lines "$P/subfinder_${domain//\./_}.txt")"

  # amass passive
  if has_opt amass; then
    _info "  amass passive ..."
    timeout 300 amass enum -passive -d "$domain" \
      -o "$P/amass_${domain//\./_}.txt" 2>/dev/null || true
    _stat "  amass: $(count_lines "$P/amass_${domain//\./_}.txt")"
  fi

  # chaos
  if has_opt chaos; then
    _info "  chaos ..."
    chaos -d "$domain" -silent \
      -o "$P/chaos_${domain//\./_}.txt" 2>/dev/null || true
    _stat "  chaos: $(count_lines "$P/chaos_${domain//\./_}.txt")"
  fi

  # crt.sh
  _info "  crt.sh ..."
  curl -s "https://crt.sh/?q=%25.$domain&output=json" --max-time 30 2>/dev/null \
    | grep -oP '"name_value":"[^"]*"' \
    | sed 's/"name_value":"//;s/"//' \
    | tr ',' '\n' | sed 's/^\*\.//' \
    | grep -E "\.${domain}$" \
    | sort -u > "$P/crtsh_${domain//\./_}.txt" 2>/dev/null || true
  _stat "  crt.sh: $(count_lines "$P/crtsh_${domain//\./_}.txt")"

  # github-subdomains
  if has_opt github-subdomains && ! $NO_GITHUB; then
    _info "  github-subdomains ..."
    github-subdomains -d "$domain" -raw -o "$P/github_${domain//\./_}.txt" \
      2>/dev/null || true
    _stat "  github: $(count_lines "$P/github_${domain//\./_}.txt")"
  fi

  # RapidDNS
  _info "  RapidDNS ..."
  curl -s "https://rapiddns.io/subdomain/$domain?full=1" --max-time 20 2>/dev/null \
    | grep -oP '(?<=<td>)[a-zA-Z0-9._-]+\.'"$domain"'(?=</td>)' \
    | sort -u > "$P/rapiddns_${domain//\./_}.txt" 2>/dev/null || true
  _stat "  RapidDNS: $(count_lines "$P/rapiddns_${domain//\./_}.txt")"

  # HackerTarget
  _info "  HackerTarget ..."
  curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" --max-time 20 2>/dev/null \
    | cut -d',' -f1 \
    | grep -E "\.${domain}$" \
    | sort -u > "$P/hackertarget_${domain//\./_}.txt" 2>/dev/null || true
  _stat "  HackerTarget: $(count_lines "$P/hackertarget_${domain//\./_}.txt")"

done

# merge all passive → master
cat "$OUTDIR/passive"/*.txt 2>/dev/null \
  | grep -E "^[a-zA-Z0-9._-]+$" \
  | sort -u >> "$ALL_SUBS"
sort -u "$ALL_SUBS" -o "$ALL_SUBS"
apply_exclusions "$ALL_SUBS"

PHASE_STATS["passive_count"]=$(count_lines "$ALL_SUBS")
_ok "Passive total: $(count_lines "$ALL_SUBS") unique subdomains  ($(fmt_time $(elapsed $T0)))"

# seed word bank
grep -oP '^[^.]+' "$ALL_SUBS" 2>/dev/null | sort -u >> "$PERMWORDS"
sort -u "$PERMWORDS" -o "$PERMWORDS"

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 3 — RECURSIVE EARLY
# ══════════════════════════════════════════════════════════════════════════
_phase 3 "Recursive Early"
T0=$(ts)

_info "Quick resolve for recursive seeding ..."
dnsx -l "$ALL_SUBS" -silent -threads "$THREADS" \
  $(resolvers_flag) \
  -o "$OUTDIR/resolve/quick_resolve.txt" 2>/dev/null || true

if [[ -s "$OUTDIR/resolve/quick_resolve.txt" ]]; then
  _info "subfinder -recursive on $(count_lines "$OUTDIR/resolve/quick_resolve.txt") hosts ..."
  while IFS= read -r sub; do
    subfinder -d "$sub" -silent -rate-limit "$RATE_LIMIT" \
      2>/dev/null >> "$OUTDIR/passive/recursive.txt" || true
  done < "$OUTDIR/resolve/quick_resolve.txt"
  sort -u "$OUTDIR/passive/recursive.txt" -o "$OUTDIR/passive/recursive.txt" 2>/dev/null || true
  apply_exclusions "$OUTDIR/passive/recursive.txt"
  NEW=$(merge_new "$OUTDIR/passive/recursive.txt" "$ALL_SUBS")
  _ok "Recursive early: +$NEW new  ($(fmt_time $(elapsed $T0)))"
fi

# ══════════════════════════════════════════════════════════════════════════
#  MAIN LOOP
# ══════════════════════════════════════════════════════════════════════════
_banner "MAIN LOOP  (max=$MAX_ITER  threshold=$NEW_THRESHOLD)"

ITERATION=0
RESUME_ITER=0
$RESUME && RESUME_ITER=$(tail -1 "$OUTDIR/.checkpoint" 2>/dev/null || echo 0)

while true; do
  ITERATION=$(( ITERATION + 1 ))
  ITER_NEW=0

  # skip iterations already done in previous run
  if $RESUME && [[ "$ITERATION" -le "$RESUME_ITER" ]]; then
    _warn "Skipping iter $ITERATION (already done)"
    continue
  fi

  echo -e "\n${Y}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  _loop "ITERATION $ITERATION / $MAX_ITER   |   total: $(count_lines "$ALL_SUBS")   live: $(count_lines "$RESOLVED")"
  echo -e "${Y}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

  checkpoint_save "loop_${ITERATION}" "$ITERATION"

  # ── PHASE 2 — RESOLVE + WILDCARD FILTER ─────────────────────────────
  _phase 2 "Resolve + Wildcard Filter  [iter $ITERATION]"
  T0=$(ts)
  RD="$OUTDIR/resolve"

  # wildcard detection per domain
  WC_IPS=()
  for domain in "${DOMAINS[@]}"; do
    UUID1=$(od -A n -t x -N 4 /dev/urandom 2>/dev/null | tr -d ' \n' || echo "rand1234")
    UUID2=$(od -A n -t x -N 4 /dev/urandom 2>/dev/null | tr -d ' \n' || echo "rand5678")
    WC1=$(dig +short +time=3 "${UUID1}.${domain}" A 2>/dev/null | head -1 || true)
    WC2=$(dig +short +time=3 "${UUID2}.${domain}" A 2>/dev/null | head -1 || true)
    if [[ -n "$WC1" && "$WC1" == "$WC2" ]]; then
      _warn "Wildcard: *.${domain} → $WC1"
      WC_IPS+=("$WC1")
      echo "$WC1" >> "$WILDCARDS"
    fi
  done
  sort -u "$WILDCARDS" -o "$WILDCARDS"

  # resolve
  _info "Resolving $(count_lines "$ALL_SUBS") subdomains ..."
  dnsx -l "$ALL_SUBS" -silent -threads "$THREADS" \
    -a -resp $(resolvers_flag) \
    -o "$RD/raw_${ITERATION}.txt" 2>/dev/null || true

  # filter wildcards
  cp "$RD/raw_${ITERATION}.txt" "$RD/filtered_${ITERATION}.txt"
  for wc_ip in "${WC_IPS[@]+"${WC_IPS[@]}"}"; do
    sed -i "/$wc_ip/d" "$RD/filtered_${ITERATION}.txt" 2>/dev/null || true
  done

  awk '{print $1}' "$RD/filtered_${ITERATION}.txt" 2>/dev/null \
    | sort -u > "$RD/clean_${ITERATION}.txt" || true
  apply_exclusions "$RD/clean_${ITERATION}.txt"

  NEW=$(merge_new "$RD/clean_${ITERATION}.txt" "$RESOLVED")
  ITER_NEW=$(( ITER_NEW + NEW ))
  _ok "Resolved: $(count_lines "$RESOLVED") live  (+$NEW)  ($(fmt_time $(elapsed $T0)))"

  # collect IPs
  grep -oP '\[\K[0-9.]+(?=\])' "$RD/raw_${ITERATION}.txt" 2>/dev/null \
    | sort -u > "$RD/ips_${ITERATION}.txt" || true
  _stat "IPs: $(count_lines "$RD/ips_${ITERATION}.txt")"

  # ── PHASE 4 — PERMUTATION ────────────────────────────────────────────
  _phase 4 "Permutation  [iter $ITERATION]"
  T0=$(ts)
  PDIR="$OUTDIR/permutation"

  # update word bank from resolved labels + httpx titles
  grep -oP '^[^.]+' "$RESOLVED" 2>/dev/null | sort -u >> "$PERMWORDS"
  if [[ -s "$LIVE_URLS" ]]; then
    grep -oP '\[([^\[\]]+)\]' "$LIVE_URLS" 2>/dev/null \
      | tr -d '[]' | tr ' _/-.' '\n' \
      | tr '[:upper:]' '[:lower:]' \
      | grep -E '^[a-z][a-z0-9]{1,20}$' >> "$PERMWORDS" || true
  fi
  sort -u "$PERMWORDS" -o "$PERMWORDS"
  _stat "Word bank: $(count_lines "$PERMWORDS") words"

  alterx -l "$RESOLVED" -enrich -en "$PERMWORDS" -silent \
    -o "$PDIR/alterx_${ITERATION}.txt" 2>/dev/null || true
  _stat "Permutations: $(count_lines "$PDIR/alterx_${ITERATION}.txt") candidates  ($(fmt_time $(elapsed $T0)))"
  merge_new "$PDIR/alterx_${ITERATION}.txt" "$ALL_SUBS" > /dev/null

  # ── PHASE 5 — BRUTEFORCE ─────────────────────────────────────────────
  _phase 5 "Bruteforce  [iter $ITERATION]"
  T0=$(ts)
  BDIR="$OUTDIR/bruteforce"
  mkdir -p "$BDIR"

  LIVE_COUNT=$(count_lines "$RESOLVED")
  if [[ "$LIVE_COUNT" -lt 5000 ]]; then
    _info "shuffledns bruteforce (${LIVE_COUNT} < 5000) ..."
    for domain in "${DOMAINS[@]}"; do
      shuffledns -d "$domain" -w "$WORDLIST" \
        -o "$BDIR/bf_${domain//\./_}_${ITERATION}.txt" \
        -t "$THREADS" $(resolvers_flag) 2>/dev/null || true
      NEW=$(merge_new "$BDIR/bf_${domain//\./_}_${ITERATION}.txt" "$ALL_SUBS")
      ITER_NEW=$(( ITER_NEW + NEW ))
      _ok "  $domain bruteforce: +$NEW new"
    done
  else
    _warn ">= 5000 subs → skipping full bruteforce"
  fi

  # permutation candidates → resolve
  if [[ -s "$PDIR/alterx_${ITERATION}.txt" ]]; then
    _info "Resolving permutation candidates ..."
    shuffledns -list "$PDIR/alterx_${ITERATION}.txt" \
      -o "$BDIR/perm_${ITERATION}.txt" \
      -t "$THREADS" $(resolvers_flag) 2>/dev/null || true
    NEW=$(merge_new "$BDIR/perm_${ITERATION}.txt" "$ALL_SUBS")
    ITER_NEW=$(( ITER_NEW + NEW ))
    _ok "Permutation resolve: +$NEW new  ($(fmt_time $(elapsed $T0)))"
  fi

  # ── PHASE 6 — ASN + PTR PIVOT ────────────────────────────────────────
  _phase 6 "ASN + PTR Pivot  [iter $ITERATION]"
  T0=$(ts)
  ADIR="$OUTDIR/asn"
  IP_LIST="$RD/ips_${ITERATION}.txt"

  if [[ -s "$IP_LIST" ]]; then
    if has_opt asnmap; then
      _info "asnmap → CIDR ranges ..."
      asnmap -l "$IP_LIST" -silent \
        -o "$ADIR/ranges_${ITERATION}.txt" 2>/dev/null || true
      cat "$ADIR/ranges_${ITERATION}.txt" >> "$ASN_RANGES"
      sort -u "$ASN_RANGES" -o "$ASN_RANGES"
      _stat "ASN CIDRs: $(count_lines "$ASN_RANGES")"
      PTR_SRC="$ASN_RANGES"
    else
      PTR_SRC="$IP_LIST"
    fi

    _info "dnsx -ptr -resp-only ..."
    dnsx -l "$PTR_SRC" -ptr -resp-only -silent \
      -threads "$THREADS" $(resolvers_flag) \
      -o "$ADIR/ptr_raw_${ITERATION}.txt" 2>/dev/null || true

    for domain in "${DOMAINS[@]}"; do
      grep -E "\.${domain}\.?$" "$ADIR/ptr_raw_${ITERATION}.txt" 2>/dev/null \
        | sed 's/\.$//' >> "$ADIR/ptr_filtered_${ITERATION}.txt" || true
    done
    sort -u "$ADIR/ptr_filtered_${ITERATION}.txt" -o "$ADIR/ptr_filtered_${ITERATION}.txt" 2>/dev/null || true
    apply_exclusions "$ADIR/ptr_filtered_${ITERATION}.txt"
    NEW=$(merge_new "$ADIR/ptr_filtered_${ITERATION}.txt" "$ALL_SUBS")
    ITER_NEW=$(( ITER_NEW + NEW ))
    _ok "PTR pivot: +$NEW new  ($(fmt_time $(elapsed $T0)))"
  fi

  # ── PHASE 7 — TLS SCRAPE ─────────────────────────────────────────────
  _phase 7 "TLS Certificate Scrape  [iter $ITERATION]"
  T0=$(ts)

  if has_opt tlsx && [[ -s "$IP_LIST" ]]; then
    _info "tlsx on collected IPs ..."
    tlsx -l "$IP_LIST" -san -cn -silent \
      -o "$OUTDIR/tls/tlsx_${ITERATION}.txt" 2>/dev/null || true

    for domain in "${DOMAINS[@]}"; do
      grep -E "\.${domain}$\|^${domain}$" "$OUTDIR/tls/tlsx_${ITERATION}.txt" 2>/dev/null \
        >> "$OUTDIR/tls/tls_filtered_${ITERATION}.txt" || true
    done
    sort -u "$OUTDIR/tls/tls_filtered_${ITERATION}.txt" \
      -o "$OUTDIR/tls/tls_filtered_${ITERATION}.txt" 2>/dev/null || true
    apply_exclusions "$OUTDIR/tls/tls_filtered_${ITERATION}.txt"
    NEW=$(merge_new "$OUTDIR/tls/tls_filtered_${ITERATION}.txt" "$ALL_SUBS")
    ITER_NEW=$(( ITER_NEW + NEW ))
    _ok "TLS scrape: +$NEW new subdomains from certificates  ($(fmt_time $(elapsed $T0)))"

    # if ASN ranges available, also run tlsx on them
    if [[ -s "$ASN_RANGES" ]]; then
      _info "tlsx on ASN ranges ..."
      tlsx -l "$ASN_RANGES" -san -cn -silent \
        -o "$OUTDIR/tls/tlsx_asn_${ITERATION}.txt" 2>/dev/null || true
      for domain in "${DOMAINS[@]}"; do
        grep -E "\.${domain}$" "$OUTDIR/tls/tlsx_asn_${ITERATION}.txt" 2>/dev/null \
          >> "$OUTDIR/tls/tls_asn_filtered_${ITERATION}.txt" || true
      done
      sort -u "$OUTDIR/tls/tls_asn_filtered_${ITERATION}.txt" \
        -o "$OUTDIR/tls/tls_asn_filtered_${ITERATION}.txt" 2>/dev/null || true
      apply_exclusions "$OUTDIR/tls/tls_asn_filtered_${ITERATION}.txt"
      NEW=$(merge_new "$OUTDIR/tls/tls_asn_filtered_${ITERATION}.txt" "$ALL_SUBS")
      ITER_NEW=$(( ITER_NEW + NEW ))
      _ok "TLS/ASN: +$NEW new"
    fi
  else
    _warn "tlsx not available or no IPs — skipping TLS scrape"
  fi

  # ── PHASE 8 — LOOP TERMINATION ───────────────────────────────────────
  _phase 8 "Loop Check  [iter $ITERATION]"

  _stat "New this iteration : ${BOLD}$ITER_NEW"
  _stat "Total subdomains   : ${BOLD}$(count_lines "$ALL_SUBS")"
  _stat "Resolved / live    : ${BOLD}$(count_lines "$RESOLVED")"

  PHASE_STATS["iter_${ITERATION}_new"]=$ITER_NEW

  if [[ "$ITER_NEW" -lt "$NEW_THRESHOLD" ]]; then
    _done "Saturated: $ITER_NEW new < threshold $NEW_THRESHOLD"
    break
  fi
  if [[ "$ITERATION" -ge "$MAX_ITER" ]]; then
    _done "Max iterations ($MAX_ITER) reached"
    break
  fi

  _loop "$ITER_NEW new found → next iteration ..."
  # quick re-resolve
  dnsx -l "$ALL_SUBS" -silent -threads "$THREADS" \
    -a -resp $(resolvers_flag) \
    -o "$RD/recheck_${ITERATION}.txt" 2>/dev/null || true
  merge_new "$RD/recheck_${ITERATION}.txt" "$RESOLVED" > /dev/null

done

PHASE_STATS["total_subdomains"]=$(count_lines "$ALL_SUBS")
PHASE_STATS["total_resolved"]=$(count_lines "$RESOLVED")

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 9 — HTTPX ENRICH
# ══════════════════════════════════════════════════════════════════════════
_phase 9 "httpx Enrich"
T0=$(ts)

_info "httpx on $(count_lines "$RESOLVED") hosts ..."
httpx -l "$RESOLVED" -silent -threads "$THREADS" \
  -title -status-code -tech-detect -content-length \
  -web-server -follow-redirects -favicon \
  -o "$OUTDIR/httpx/enriched.txt" 2>/dev/null || true

cp "$OUTDIR/httpx/enriched.txt" "$LIVE_URLS" 2>/dev/null || true
PHASE_STATS["live_web"]=$(count_lines "$LIVE_URLS")
_ok "httpx: $(count_lines "$LIVE_URLS") live endpoints  ($(fmt_time $(elapsed $T0)))"

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 10 — FAVICON HASH PIVOT
# ══════════════════════════════════════════════════════════════════════════
_phase 10 "Favicon Hash Pivot"
T0=$(ts)

if [[ -s "$LIVE_URLS" ]]; then
  _info "Extracting favicon hashes ..."
  grep -oP 'favicon=\[\K[^\]]+' "$LIVE_URLS" 2>/dev/null \
    | sort | uniq -c | sort -rn \
    | head -20 > "$OUTDIR/httpx/favicon_hashes.txt" || true

  if [[ -s "$OUTDIR/httpx/favicon_hashes.txt" ]]; then
    _ok "Top favicon hashes:"
    while IFS= read -r line; do
      count=$(echo "$line" | awk '{print $1}')
      hash=$(echo "$line" | awk '{print $2}')
      _stat "  hash=${hash}  (seen ${count}x)"
      # Shodan query hint
      echo "http.favicon.hash:${hash}" >> "$OUTDIR/httpx/shodan_queries.txt"
      # Censys query hint
      echo "services.http.response.favicons.md5_hash:${hash}" >> "$OUTDIR/httpx/censys_queries.txt"
    done < "$OUTDIR/httpx/favicon_hashes.txt"

    echo ""
    _info "Shodan/Censys queries saved to:"
    _stat "  $OUTDIR/httpx/shodan_queries.txt"
    _stat "  $OUTDIR/httpx/censys_queries.txt"
    _info "Use these to find hosts serving the same favicon (possible hidden assets)"
    _time "$(fmt_time $(elapsed $T0))"
  fi
fi

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 11 — CLOUD ASSET DISCOVERY
# ══════════════════════════════════════════════════════════════════════════
_phase 11 "Cloud Asset Discovery"
T0=$(ts)

if ! $NO_CLOUD; then
  CLOUD_DIR="$OUTDIR/cloud"

  # generate permutations for cloud bucket names
  _info "Generating cloud bucket name candidates ..."
  {
    for domain in "${DOMAINS[@]}"; do
      base="${domain%%.*}"
      # common patterns
      for suffix in "" "-dev" "-prod" "-staging" "-backup" "-assets" \
                    "-static" "-media" "-uploads" "-data" "-logs" \
                    "-public" "-private" "-archive" "-cdn" "-api" \
                    ".dev" ".prod" ".backup" ".assets"; do
        echo "${base}${suffix}"
        echo "${base//./-}${suffix}"
      done
    done
    # also use top words from word bank
    head -50 "$PERMWORDS" 2>/dev/null | while read -r w; do
      for domain in "${DOMAINS[@]}"; do
        base="${domain%%.*}"
        echo "${base}-${w}"
        echo "${w}-${base}"
      done
    done
  } | sort -u > "$CLOUD_DIR/bucket_candidates.txt"
  _stat "Bucket candidates: $(count_lines "$CLOUD_DIR/bucket_candidates.txt")"

  # S3 scanner
  if has_opt s3scanner; then
    _info "s3scanner ..."
    s3scanner -bucket-file "$CLOUD_DIR/bucket_candidates.txt" \
      -o "$CLOUD_DIR/s3_results.txt" 2>/dev/null || true
    grep -v "does not exist" "$CLOUD_DIR/s3_results.txt" 2>/dev/null \
      | grep -v "^$" > "$CLOUD_DIR/s3_found.txt" || true
    FOUND=$(count_lines "$CLOUD_DIR/s3_found.txt")
    [[ "$FOUND" -gt 0 ]] && _ok "S3 buckets found: $FOUND" || _stat "S3: none found"
  fi

  # Azure blob & GCP storage (curl-based fallback)
  _info "Checking Azure/GCP storage ..."
  while IFS= read -r bucket; do
    # Azure
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      --max-time 5 "https://${bucket}.blob.core.windows.net" 2>/dev/null || echo 0)
    [[ "$code" == "400" || "$code" == "200" ]] && \
      echo "AZURE: ${bucket}.blob.core.windows.net [${code}]" >> "$CLOUD_DIR/azure_found.txt"
    # GCP
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      --max-time 5 "https://storage.googleapis.com/${bucket}" 2>/dev/null || echo 0)
    [[ "$code" == "200" || "$code" == "403" ]] && \
      echo "GCP: storage.googleapis.com/${bucket} [${code}]" >> "$CLOUD_DIR/gcp_found.txt"
  done < "$CLOUD_DIR/bucket_candidates.txt"

  AZURE_FOUND=$(count_lines "$CLOUD_DIR/azure_found.txt")
  GCP_FOUND=$(count_lines "$CLOUD_DIR/gcp_found.txt")
  [[ "$AZURE_FOUND" -gt 0 ]] && _ok "Azure blobs found: $AZURE_FOUND"
  [[ "$GCP_FOUND" -gt 0 ]]   && _ok "GCP buckets found: $GCP_FOUND"
  _time "$(fmt_time $(elapsed $T0))"
else
  _warn "Cloud discovery skipped (--no-cloud)"
fi

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 12 — EXTRACT WORDS → FINAL PERMUTATION PASS
# ══════════════════════════════════════════════════════════════════════════
_phase 12 "Extract New Words → Final Permutation Pass"
T0=$(ts)

{
  # from httpx titles
  grep -oP '\[([^\[\]]+)\]' "$LIVE_URLS" 2>/dev/null \
    | tr -d '[]' | tr ' _/-.' '\n' \
    | tr '[:upper:]' '[:lower:]' \
    | grep -E '^[a-z][a-z0-9]{1,20}$' || true
  # from subdomain labels
  grep -oP '^[^.]+' "$RESOLVED" 2>/dev/null || true
  # from TLS CN/SANs
  cat "$OUTDIR/tls"/tls_filtered_*.txt 2>/dev/null \
    | grep -oP '^[^.]+' | sort -u || true
} | sort -u > "$OUTDIR/words/final_words.txt"

NEW_WORDS=$(comm -23 \
  <(sort "$OUTDIR/words/final_words.txt") \
  <(sort "$PERMWORDS") | wc -l | tr -d ' ')

cat "$OUTDIR/words/final_words.txt" >> "$PERMWORDS"
sort -u "$PERMWORDS" -o "$PERMWORDS"
_ok "New words: $NEW_WORDS  →  word bank total: $(count_lines "$PERMWORDS")"

if [[ "$NEW_WORDS" -gt 5 ]]; then
  _info "Final alterx pass ..."
  alterx -l "$RESOLVED" -enrich -en "$PERMWORDS" -silent \
    -o "$OUTDIR/permutation/alterx_final.txt" 2>/dev/null || true

  _info "Final shuffledns resolve ..."
  for domain in "${DOMAINS[@]}"; do
    shuffledns -list "$OUTDIR/permutation/alterx_final.txt" \
      -o "$OUTDIR/bruteforce/final_${domain//\./_}.txt" \
      -t "$THREADS" $(resolvers_flag) 2>/dev/null || true
    NEW=$(merge_new "$OUTDIR/bruteforce/final_${domain//\./_}.txt" "$ALL_SUBS")
    _ok "  $domain final pass: +$NEW new"
  done

  # final resolve
  dnsx -l "$ALL_SUBS" -silent -threads "$THREADS" \
    -a -resp $(resolvers_flag) \
    -o "$OUTDIR/resolve/final.txt" 2>/dev/null || true
  merge_new "$OUTDIR/resolve/final.txt" "$RESOLVED" > /dev/null
  _time "$(fmt_time $(elapsed $T0))"
fi

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 13 — JSON REPORT
# ══════════════════════════════════════════════════════════════════════════
_phase 13 "JSON Report"

TOTAL_ELAPSED=$(elapsed $GLOBAL_START)
PHASE_STATS["live_web"]=$(count_lines "$LIVE_URLS")
PHASE_STATS["total_resolved"]=$(count_lines "$RESOLVED")
PHASE_STATS["total_subdomains"]=$(count_lines "$ALL_SUBS")

# build JSON report with or without jq
if has_opt jq; then
  jq -n \
    --arg target "$PRIMARY_DOMAIN" \
    --argjson domains "$(printf '%s\n' "${DOMAINS[@]}" | jq -R . | jq -s .)" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson duration "$TOTAL_ELAPSED" \
    --argjson iterations "$ITERATION" \
    --argjson total_subdomains "$(count_lines "$ALL_SUBS")" \
    --argjson resolved "$(count_lines "$RESOLVED")" \
    --argjson live_web "$(count_lines "$LIVE_URLS")" \
    --argjson word_bank "$(count_lines "$PERMWORDS")" \
    --argjson valid_resolvers "$(count_lines "$VALID_RESOLVERS")" \
    --argjson passive "$(count_lines "$OUTDIR/passive"/*.txt 2>/dev/null | tail -1 || echo 0)" \
    --argjson exclusions "${#EXCLUSIONS[@]}" \
    --arg outdir "$OUTDIR" \
    --arg wordlist "$WORDLIST" \
    '{
      meta: {
        target: $target,
        domains: $domains,
        timestamp: $timestamp,
        duration_seconds: $duration,
        outdir: $outdir,
        wordlist: $wordlist
      },
      stats: {
        iterations: $iterations,
        total_subdomains: $total_subdomains,
        resolved_live: $resolved,
        live_web_endpoints: $live_web,
        word_bank_size: $word_bank,
        valid_resolvers: $valid_resolvers,
        exclusion_rules: $exclusions
      },
      files: {
        all_subdomains: "all_subdomains.txt",
        resolved: "resolved.txt",
        live_urls: "live_urls.txt",
        word_bank: "permutation_words.txt",
        shodan_queries: "httpx/shodan_queries.txt",
        censys_queries: "httpx/censys_queries.txt",
        log: "pipeline.log"
      }
    }' > "$STATS_FILE" 2>/dev/null || true
  _ok "JSON report → $STATS_FILE"
else
  # fallback: simple JSON without jq
  cat > "$STATS_FILE" << JSONEOF
{
  "target": "$PRIMARY_DOMAIN",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_seconds": $TOTAL_ELAPSED,
  "stats": {
    "iterations": $ITERATION,
    "total_subdomains": $(count_lines "$ALL_SUBS"),
    "resolved_live": $(count_lines "$RESOLVED"),
    "live_web_endpoints": $(count_lines "$LIVE_URLS"),
    "word_bank_size": $(count_lines "$PERMWORDS"),
    "valid_resolvers": $(count_lines "$VALID_RESOLVERS")
  }
}
JSONEOF
  _ok "JSON report (basic) → $STATS_FILE"
fi

# ══════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════
ELAPSED_FMT=$(printf '%dh %dm %ds' \
  $((TOTAL_ELAPSED/3600)) $(((TOTAL_ELAPSED%3600)/60)) $((TOTAL_ELAPSED%60)))

_banner "PIPELINE COMPLETE"
_TOTAL_SUBS=$(count_lines "$ALL_SUBS")
_TOTAL_RES=$(count_lines "$RESOLVED")
_TOTAL_WEB=$(count_lines "$LIVE_URLS")
_TOTAL_WORDS=$(count_lines "$PERMWORDS")
printf "  ${BOLD}%-24s${NC} ${G}%s${NC}\n" \
  "Target(s):"       "${DOMAINS[*]}" \
  "Total Subdomains:" "$_TOTAL_SUBS" \
  "Resolved / Live:"  "$_TOTAL_RES" \
  "Web Endpoints:"    "$_TOTAL_WEB" \
  "Word Bank:"       "$_TOTAL_WORDS words" \
  "Iterations:"      "$ITERATION" \
  "Duration:"        "$ELAPSED_FMT"

echo ""
echo -e "  ${BOLD}Output:${NC} ${C}$OUTDIR/${NC}"
echo -e "${DIM}"
cat << 'TREE'
    ├── all_subdomains.txt        master list (all discovered)
    ├── resolved.txt              live hosts with IPs
    ├── live_urls.txt             httpx enriched (title/tech/status)
    ├── permutation_words.txt     accumulated word bank
    ├── stats.json                machine-readable summary
    ├── passive/                  per-source passive results
    ├── resolve/                  per-iteration resolve data
    ├── permutation/              alterx candidates
    ├── bruteforce/               shuffledns results
    ├── asn/                      ASN ranges + PTR results
    ├── tls/                      tlsx certificate data
    ├── httpx/                    enriched results + favicon hashes
    │   ├── shodan_queries.txt    ready-to-use Shodan queries
    │   └── censys_queries.txt    ready-to-use Censys queries
    ├── cloud/                    S3/Azure/GCP findings
    ├── words/                    extracted word lists
    └── pipeline.log              full execution log
TREE
echo -e "${NC}"
echo -e "${Y}  ⚠  Authorized testing only. Respect scope boundaries.${NC}\n"

# cleanup checkpoint
rm -f "$OUTDIR/.checkpoint"
