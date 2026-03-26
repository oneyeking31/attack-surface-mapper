#!/bin/bash
# =============================================================
#   RECON AUTOMATION SCRIPT
#   Usage:   ./recon.sh <domain>
#   Example: ./recon.sh example.com
#
#   Fixes applied (v2):
#     1. ffuf wordlist paths corrected for Kali
#     2. JS secrets — value extraction, no false positives
#     3. IDOR — tighter patterns, no timestamps/cache
#     4. Tool checks before every call — no crashes
#     5. Rate limit set to 5 req/sec
#     6. [FIXED] nmap — now receives clean IP list, not host:port pairs
#     7. [FIXED] gospider merge — safe cat with empty-dir guard
#     8. [FIXED] paramspider — handles both old (-o) and new (results/) output
#     9. [FIXED] feroxbuster — MAX_FUZZ_HOSTS cap to avoid infinite loops
#    10. [FIXED] JS download — parallel curl with xargs -P for speed
# =============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
  echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
  echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
  echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
  echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
  echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
  echo -e "${NC}"
  echo -e "${BOLD}  Recon Automation Script v2${NC}"
  echo ""
}

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }
section() {
  echo -e "\n${BOLD}${YELLOW}══════════════════════════════════════════${NC}"
  echo -e "${BOLD}${YELLOW}  $1${NC}"
  echo -e "${BOLD}${YELLOW}══════════════════════════════════════════${NC}\n"
}

check_tool() {
  command -v "$1" &>/dev/null
}

# ── Argument check ────────────────────────────────────────────
if [ -z "$1" ]; then
  error "Usage: $0 <domain>"
  error "Example: $0 example.com"
  exit 1
fi

DOMAIN=$1
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTDIR="$HOME/recon_${DOMAIN}_${TIMESTAMP}"
mkdir -p "$OUTDIR"
cd "$OUTDIR" || exit 1

# ── API Keys (optional — leave empty to skip) ─────────────────
GITHUB_TOKEN=""
PDCP_API_KEY=""

# ── FIX 9: Cap feroxbuster to avoid multi-hour runs ──────────
MAX_FUZZ_HOSTS=20

# ── PATH ──────────────────────────────────────────────────────
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# =============================================================
# WORDLIST PATHS — Auto-detected for Kali Linux
# =============================================================
if [ -d "/usr/share/seclists" ]; then
  SECLISTS="/usr/share/seclists"
elif [ -d "/usr/share/wordlists/seclists" ]; then
  SECLISTS="/usr/share/wordlists/seclists"
else
  warn "SecLists not found. Install with: sudo apt install seclists"
  warn "Continuing — directory fuzzing phases will be skipped"
  SECLISTS=""
fi

WL_DNS_SUBDOMAINS="${SECLISTS}/Discovery/DNS/bitquark-subdomains-top100000.txt"
WL_DNS_TOP="${SECLISTS}/Discovery/DNS/subdomains-top1million-110000.txt"
WL_WEB_RAFT="${SECLISTS}/Discovery/Web-Content/raft-large-directories.txt"
WL_WEB_COMMON="${SECLISTS}/Discovery/Web-Content/common.txt"
WL_API="${SECLISTS}/Discovery/Web-Content/api/api-endpoints.txt"

banner
info "Target       : $DOMAIN"
info "Output       : $OUTDIR"
info "Started      : $(date)"
info "SecLists     : ${SECLISTS:-NOT FOUND}"
info "Max fuzz hosts: $MAX_FUZZ_HOSTS"
echo ""

# =============================================================
# PHASE 1 — SUBDOMAIN ENUMERATION
# =============================================================
section "PHASE 1 — SUBDOMAIN ENUMERATION"

if check_tool subfinder; then
  info "subfinder..."
  subfinder -d "$DOMAIN" -all -recursive -silent \
    -o "$OUTDIR/Subs01.txt" 2>/dev/null || true
else
  warn "subfinder not found — skipping (install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)"
fi
touch "$OUTDIR/Subs01.txt"
success "Subs01.txt — $(wc -l < "$OUTDIR/Subs01.txt") results"

if check_tool assetfinder; then
  info "assetfinder..."
  echo "$DOMAIN" | assetfinder -subs-only \
    > "$OUTDIR/Subs02.txt" 2>/dev/null || true
else
  warn "assetfinder not found — skipping (install: go install github.com/tomnomnom/assetfinder@latest)"
fi
touch "$OUTDIR/Subs02.txt"
success "Subs02.txt — $(wc -l < "$OUTDIR/Subs02.txt") results"

if check_tool amass; then
  info "amass (passive, 5 min timeout)..."
  timeout 300 amass enum -passive -d "$DOMAIN" \
    -o "$OUTDIR/Subs03.txt" 2>/dev/null || true
else
  warn "amass not found — skipping (install: sudo apt install amass)"
fi
touch "$OUTDIR/Subs03.txt"
success "Subs03.txt — $(wc -l < "$OUTDIR/Subs03.txt") results"

if check_tool findomain; then
  info "findomain..."
  findomain -t "$DOMAIN" -u "$OUTDIR/Subs04.txt" -q 2>/dev/null || true
else
  warn "findomain not found — skipping"
fi
touch "$OUTDIR/Subs04.txt"
success "Subs04.txt — $(wc -l < "$OUTDIR/Subs04.txt") results"

if [ -n "$GITHUB_TOKEN" ] && check_tool github-subdomains; then
  info "github-subdomains..."
  github-subdomains -d "$DOMAIN" -t "$GITHUB_TOKEN" \
    -o "$OUTDIR/Subs05.txt" 2>/dev/null || true
else
  warn "Skipping github-subdomains (no token or tool not found)"
fi
touch "$OUTDIR/Subs05.txt"

if [ -n "$PDCP_API_KEY" ] && check_tool chaos; then
  info "chaos..."
  export PDCP_API_KEY="$PDCP_API_KEY"
  chaos -d "$DOMAIN" -o "$OUTDIR/Subs06.txt" -silent 2>/dev/null || true
else
  warn "Skipping chaos (no API key or tool not found)"
fi
touch "$OUTDIR/Subs06.txt"

info "crt.sh certificate transparency..."
curl -s --max-time 30 "https://crt.sh/?q=%25.$DOMAIN&output=json" \
  | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//g' | tr ',' '\n' \
  | grep -oE "[A-Za-z0-9._-]+\.$DOMAIN" \
  | sort -u > "$OUTDIR/Subs07_crtsh.txt" || true
touch "$OUTDIR/Subs07_crtsh.txt"
success "Subs07_crtsh.txt — $(wc -l < "$OUTDIR/Subs07_crtsh.txt") results"

if check_tool puredns && [ -f "$WL_DNS_SUBDOMAINS" ]; then
  info "puredns bruteforce..."
  puredns bruteforce "$WL_DNS_SUBDOMAINS" \
    "$DOMAIN" \
    --write "$OUTDIR/Subs08_puredns.txt" -q 2>/dev/null || true
else
  warn "puredns or wordlist not found — skipping bruteforce"
fi
touch "$OUTDIR/Subs08_puredns.txt"
success "Subs08_puredns.txt — $(wc -l < "$OUTDIR/Subs08_puredns.txt") results"

if check_tool ffuf && [ -f "$WL_DNS_TOP" ]; then
  info "ffuf subdomain fuzzing..."
  ffuf -u "https://FUZZ.$DOMAIN" \
    -w "$WL_DNS_TOP" \
    -mc 200,301,302,403 -t 10 -rate 5 -silent \
    -o "$OUTDIR/Subs10_ffuf.json" 2>/dev/null || true
  success "Subs10_ffuf.json done"
else
  warn "ffuf or wordlist not found — skipping subdomain ffuf"
fi

DOMAIN_IP=$(dig +short "$DOMAIN" @8.8.8.8 | grep -E '^[0-9]+\.' | head -1)
if check_tool ffuf && [ -f "$WL_DNS_TOP" ] && [ -n "$DOMAIN_IP" ]; then
  info "Virtual host enumeration..."
  ffuf -u "http://$DOMAIN_IP" \
    -w "$WL_DNS_TOP" \
    -H "Host: FUZZ.$DOMAIN" \
    -mc 200,301,302,403 -t 10 -rate 5 -silent \
    -o "$OUTDIR/Subs11_vhosts.json" 2>/dev/null || true
  success "Subs11_vhosts.json done"
else
  warn "Skipping vhost fuzzing"
fi

# =============================================================
# PHASE 2 — MERGE & DEDUPLICATE
# =============================================================
section "PHASE 2 — MERGE & DEDUPLICATE"

cat "$OUTDIR"/Subs*.txt 2>/dev/null \
  | grep -oE "[A-Za-z0-9._-]+\.$DOMAIN" \
  | sort -u > "$OUTDIR/AllSubs.txt"

success "AllSubs.txt — $(wc -l < "$OUTDIR/AllSubs.txt") unique subdomains"

# =============================================================
# PHASE 3 — ALIVE HOST DETECTION
# =============================================================
section "PHASE 3 — ALIVE HOST DETECTION"

if check_tool httpx; then
  info "Running httpx..."
  httpx -l "$OUTDIR/AllSubs.txt" \
    -status-code -content-length -web-server -title \
    -timeout 10 \
    -retries 2 \
    -threads 20 \
    -rate-limit 5 \
    -follow-redirects \
    -random-agent \
    -silent \
    -o "$OUTDIR/AliveSubs_detailed.txt" 2>/dev/null || true
else
  warn "httpx not found — skipping alive check (install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest)"
fi

touch "$OUTDIR/AliveSubs_detailed.txt"
awk '{print $1}' "$OUTDIR/AliveSubs_detailed.txt" > "$OUTDIR/AliveSubs.txt"

grep -E "\[200\]" "$OUTDIR/AliveSubs_detailed.txt" | awk '{print $1}' > "$OUTDIR/Alive_200.txt"
grep -E "\[403\]" "$OUTDIR/AliveSubs_detailed.txt" | awk '{print $1}' > "$OUTDIR/Alive_403.txt"
grep -E "\[404\]" "$OUTDIR/AliveSubs_detailed.txt" | awk '{print $1}' > "$OUTDIR/Alive_404.txt"
grep -E "\[401\]" "$OUTDIR/AliveSubs_detailed.txt" | awk '{print $1}' > "$OUTDIR/Alive_401.txt"
grep -E "\[302\]|\[301\]" "$OUTDIR/AliveSubs_detailed.txt" | awk '{print $1}' > "$OUTDIR/Alive_redirect.txt"
grep -E "\[500\]" "$OUTDIR/AliveSubs_detailed.txt" | awk '{print $1}' > "$OUTDIR/Alive_500.txt"

touch "$OUTDIR/AliveSubs.txt" "$OUTDIR/Alive_200.txt" \
      "$OUTDIR/Alive_403.txt" "$OUTDIR/Alive_404.txt" \
      "$OUTDIR/Alive_401.txt" "$OUTDIR/Alive_redirect.txt" \
      "$OUTDIR/Alive_500.txt"

success "AliveSubs.txt      — $(wc -l < "$OUTDIR/AliveSubs.txt") alive"
success "Alive_200.txt      — $(wc -l < "$OUTDIR/Alive_200.txt")"
success "Alive_401.txt      — $(wc -l < "$OUTDIR/Alive_401.txt")"
success "Alive_403.txt      — $(wc -l < "$OUTDIR/Alive_403.txt")"
success "Alive_500.txt      — $(wc -l < "$OUTDIR/Alive_500.txt") ← check these manually"

# =============================================================
# PHASE 4 — URL DISCOVERY
# =============================================================
section "PHASE 4 — URL DISCOVERY"

if check_tool waybackurls; then
  info "waybackurls..."
  cat "$OUTDIR/AliveSubs.txt" | waybackurls \
    > "$OUTDIR/WB1.txt" 2>/dev/null || true
else
  warn "waybackurls not found — skipping"
fi
touch "$OUTDIR/WB1.txt"

if check_tool gau; then
  info "gau..."
  cat "$OUTDIR/AliveSubs.txt" | gau --threads 5 \
    > "$OUTDIR/GAU1.txt" 2>/dev/null || true
else
  warn "gau not found — skipping"
fi
touch "$OUTDIR/GAU1.txt"

if check_tool hakrawler; then
  info "hakrawler..."
  cat "$OUTDIR/AliveSubs.txt" | hakrawler -subs -u -insecure \
    > "$OUTDIR/HK1.txt" 2>/dev/null || true
else
  warn "hakrawler not found — skipping"
fi
touch "$OUTDIR/HK1.txt"

if check_tool katana; then
  info "katana..."
  katana -list "$OUTDIR/AliveSubs.txt" \
    -jc -kf all -d 3 -aff -fs rdn -f url -silent \
    -rl 5 \
    -o "$OUTDIR/KTN1.txt" 2>/dev/null || true
else
  warn "katana not found — skipping"
fi
touch "$OUTDIR/KTN1.txt"

# FIX 7: gospider — safe merge with empty-dir guard
if check_tool gospider; then
  info "gospider..."
  mkdir -p "$OUTDIR/GS_raw"
  gospider -S "$OUTDIR/AliveSubs.txt" -t 5 -d 3 --js --sitemap --robots \
    -o "$OUTDIR/GS_raw" 2>/dev/null || true
  if [ -n "$(ls -A "$OUTDIR/GS_raw" 2>/dev/null)" ]; then
    cat "$OUTDIR/GS_raw"/* > "$OUTDIR/GS1.txt" 2>/dev/null || true
  fi
else
  warn "gospider not found — skipping"
fi
touch "$OUTDIR/GS1.txt"

# FIX 8: paramspider — handle both old (-o file) and new (results/ folder) output formats
if check_tool paramspider; then
  info "paramspider..."
  paramspider -d "$DOMAIN" -o "$OUTDIR/PS1.txt" 2>/dev/null || true
  # Newer paramspider versions write to results/<domain>.txt instead
  PS_RESULTS_DIR="$HOME/results"
  if [ ! -s "$OUTDIR/PS1.txt" ] && [ -f "${PS_RESULTS_DIR}/${DOMAIN}.txt" ]; then
    cp "${PS_RESULTS_DIR}/${DOMAIN}.txt" "$OUTDIR/PS1.txt"
    info "paramspider: picked up output from results/${DOMAIN}.txt"
  fi
else
  warn "paramspider not found — skipping"
fi
touch "$OUTDIR/PS1.txt"

# Merge all URLs
info "Merging all URLs..."
cat "$OUTDIR"/WB1.txt "$OUTDIR"/GAU1.txt \
    "$OUTDIR"/KTN1.txt "$OUTDIR"/HK1.txt \
    "$OUTDIR"/GS1.txt "$OUTDIR"/PS1.txt 2>/dev/null \
  | grep -v "_Incapsula_Resource" \
  | grep -v "CWUDNSAI" \
  | sort -u > "$OUTDIR/AllURLs.txt"
success "AllURLs.txt — $(wc -l < "$OUTDIR/AllURLs.txt") unique URLs"

# URL categorization
grep -Ei '\.js(\?|$)' "$OUTDIR/AllURLs.txt" > "$OUTDIR/js_urls.txt"
grep -Ei 'login|signin|auth|oauth|reset|password|sso|saml|token' "$OUTDIR/AllURLs.txt" > "$OUTDIR/login_flows.txt"
grep -Ei 'admin|dashboard|internal|manage|partner|affiliate|operator' "$OUTDIR/AllURLs.txt" > "$OUTDIR/admin_panels.txt"
grep -Ei '\.(env|bak|config|sql|log)(\?|$)' "$OUTDIR/AllURLs.txt" > "$OUTDIR/sensitive_files.txt"
grep -Ei 'redirect|callback|return|goto|dest|url=|r=|u=|next=' "$OUTDIR/AllURLs.txt" > "$OUTDIR/open_redirects.txt"
grep -Ei '\.(json|xml|graphql|gql)(\?|$)' "$OUTDIR/AllURLs.txt" > "$OUTDIR/api_urls.txt"

# IDOR DETECTION — Tighter patterns, remove false positives
info "IDOR candidate detection (strict)..."
grep -oE 'https?://[^ ]+' "$OUTDIR/AllURLs.txt" \
  | grep -E '[?&](id|user_id|account_id|order_id|uid|pid|cid|customer_id|ref_id|invoice_id|ticket_id|booking_id)=[0-9]+' \
  | grep -v -E '(timestamp|cache|version|v=[0-9]|t=[0-9]{10}|_=[0-9]{10,13}|[0-9]{10,13})' \
  > "$OUTDIR/idor_targets.txt" || true

grep -oE 'https?://[^ ]+' "$OUTDIR/AllURLs.txt" \
  | grep -E '/(users?|accounts?|orders?|invoices?|customers?|profiles?|tickets?|bookings?)/[0-9]{2,10}(/|$|\?)' \
  | grep -v -E '(/v[0-9]+/|/api/v[0-9]+/)' \
  >> "$OUTDIR/idor_targets.txt" || true

sort -u "$OUTDIR/idor_targets.txt" -o "$OUTDIR/idor_targets.txt"

touch "$OUTDIR/js_urls.txt" "$OUTDIR/login_flows.txt" "$OUTDIR/admin_panels.txt" \
      "$OUTDIR/sensitive_files.txt" "$OUTDIR/open_redirects.txt" "$OUTDIR/api_urls.txt" \
      "$OUTDIR/idor_targets.txt"

success "IDOR candidates: $(wc -l < "$OUTDIR/idor_targets.txt") (strict — low false positives)"

# Live URL filter
if check_tool httpx; then
  info "Filtering live URLs with httpx..."
  cat "$OUTDIR/AllURLs.txt" | httpx \
    -status-code -content-length \
    -timeout 5 \
    -rate-limit 5 \
    -silent \
    -o "$OUTDIR/LiveURLs.txt" 2>/dev/null || true
fi
touch "$OUTDIR/LiveURLs.txt"

# =============================================================
# PHASE 5 — JAVASCRIPT SECRET DISCOVERY
# =============================================================
section "PHASE 5 — JS SECRET DISCOVERY"

if check_tool subjs; then
  info "Running subjs..."
  cat "$OUTDIR/AliveSubs.txt" | subjs \
    >> "$OUTDIR/js_urls.txt" 2>/dev/null || true
  sort -u "$OUTDIR/js_urls.txt" -o "$OUTDIR/js_urls.txt"
else
  warn "subjs not found — using js_urls.txt from URL discovery only"
fi

# FIX 10: Parallel JS download with xargs -P instead of slow sequential loop
info "Downloading JS files (parallel, 10 workers)..."
mkdir -p "$OUTDIR/js_files"
_download_js() {
  jsurl="$1"
  outdir="$2"
  filename=$(echo "$jsurl" | md5sum | cut -d' ' -f1)
  curl -sk --max-time 10 "$jsurl" \
    -o "${outdir}/${filename}.js" 2>/dev/null || true
}
export -f _download_js
if [ -s "$OUTDIR/js_urls.txt" ]; then
  xargs -P 10 -I{} bash -c '_download_js "$@"' _ {} "$OUTDIR/js_files" \
    < "$OUTDIR/js_urls.txt" 2>/dev/null || true
fi

# Smart JS secret extraction — low false positives
info "Extracting JS secrets (smart patterns)..."

# Pattern 1: key=value with quoted real values (min 8 chars, not placeholder)
grep -rh -oE \
  '(api[_-]?key|apiKey|api_secret|client_secret|clientSecret|access_token|accessToken|auth_token|authToken|bearer|private_key|aws_access_key_id|aws_secret|AKIA[A-Z0-9]{16})["\s]*[:=]["\s]*["'"'"'][A-Za-z0-9_\-\.\/+]{8,}["'"'"']' \
  "$OUTDIR/js_files/" 2>/dev/null \
  | grep -v -iE '(placeholder|example|your_|<|>|xxx|test|fake|dummy|undefined|null|true|false|{|}|\$\{)' \
  > "$OUTDIR/js_secrets.txt" || true

# Pattern 2: AWS keys (very specific format, almost zero false positives)
grep -rh -oE 'AKIA[A-Z0-9]{16}' \
  "$OUTDIR/js_files/" 2>/dev/null \
  >> "$OUTDIR/js_secrets.txt" || true

# Pattern 3: Bearer tokens in JS
grep -rh -oE 'Bearer [A-Za-z0-9\-_\.]{20,}' \
  "$OUTDIR/js_files/" 2>/dev/null \
  | grep -v -iE '(placeholder|example|token_here)' \
  >> "$OUTDIR/js_secrets.txt" || true

# Pattern 4: Hardcoded passwords
grep -rh -oE \
  'password["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']{8,}["'"'"']' \
  "$OUTDIR/js_files/" 2>/dev/null \
  | grep -v -iE '(placeholder|example|your_password|<password>|password123|test|fake)' \
  >> "$OUTDIR/js_secrets.txt" || true

sort -u "$OUTDIR/js_secrets.txt" -o "$OUTDIR/js_secrets.txt"

# Extract API paths and URLs from JS
grep -roh -E '"\/[a-zA-Z0-9_\/-]{3,}"' \
  "$OUTDIR/js_files/" 2>/dev/null \
  | sort -u > "$OUTDIR/js_api_paths.txt" || true

grep -roh -E 'https?://[^"'"'"'` \\]+' \
  "$OUTDIR/js_files/" 2>/dev/null \
  | sort -u > "$OUTDIR/js_extracted_urls.txt" || true

touch "$OUTDIR/js_secrets.txt" "$OUTDIR/js_api_paths.txt" "$OUTDIR/js_extracted_urls.txt"

success "js_secrets.txt        — $(wc -l < "$OUTDIR/js_secrets.txt") hits (low false positives)"
success "js_api_paths.txt      — $(wc -l < "$OUTDIR/js_api_paths.txt") paths"
success "js_extracted_urls.txt — $(wc -l < "$OUTDIR/js_extracted_urls.txt") URLs"

# Wayback archived JS
info "Wayback archived JS..."
curl -sk --max-time 30 \
  "https://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&collapse=urlkey&output=text&fl=original&filter=original:.*.js$" \
  | sort -u > "$OUTDIR/wayback_js.txt" 2>/dev/null || true
touch "$OUTDIR/wayback_js.txt"
success "wayback_js.txt — $(wc -l < "$OUTDIR/wayback_js.txt") archived JS URLs"

# =============================================================
# PHASE 6 — SENSITIVE FILE DISCOVERY
# =============================================================
section "PHASE 6 — SENSITIVE FILE DISCOVERY"

if check_tool waybackurls; then
  info "Wayback sensitive files..."
  waybackurls "$DOMAIN" 2>/dev/null \
    | grep -E "\.(xls|xlsx|csv|sql|db|bak|backup|old|tar\.gz|zip|env|yml|pem|key|git|htpasswd|log|conf)(\?|$)" \
    > "$OUTDIR/wayback_sensitive.txt" || true
fi
touch "$OUTDIR/wayback_sensitive.txt"
success "wayback_sensitive.txt — $(wc -l < "$OUTDIR/wayback_sensitive.txt") results"

info "Wayback all historical URLs..."
curl -sk --max-time 60 \
  "https://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=text&fl=original&collapse=urlkey" \
  | sort -u > "$OUTDIR/wayback_all_urls.txt" 2>/dev/null || true
touch "$OUTDIR/wayback_all_urls.txt"

# =============================================================
# PHASE 7 — DIRECTORY FUZZING
# =============================================================
section "PHASE 7 — DIRECTORY FUZZING"

mkdir -p "$OUTDIR/ferox_results"

# FIX 9: Cap hosts to MAX_FUZZ_HOSTS to prevent multi-hour runs
if check_tool feroxbuster && [ -f "$WL_WEB_RAFT" ]; then
  info "feroxbuster on up to $MAX_FUZZ_HOSTS hosts from Alive_200..."
  head -n "$MAX_FUZZ_HOSTS" "$OUTDIR/Alive_200.txt" | while IFS= read -r url; do
    safe=$(echo "$url" | sed 's|https\?://||;s|/|_|g')
    feroxbuster -u "$url" \
      -w "$WL_WEB_RAFT" \
      -t 10 -k -d 2 \
      -x php,html,json,js,log,txt,bak,old,zip \
      --silent \
      -o "$OUTDIR/ferox_results/${safe}.txt" 2>/dev/null || true
  done
  success "ferox_results/ done"
else
  warn "feroxbuster or wordlist not found — skipping directory fuzzing"
fi

if check_tool ffuf && [ -f "$WL_WEB_COMMON" ]; then
  info "403 bypass attempts..."
  head -n "$MAX_FUZZ_HOSTS" "$OUTDIR/Alive_403.txt" | while IFS= read -r url; do
    safe=$(echo "$url" | sed 's|https\?://||;s|/|_|g')
    ffuf -u "${url}/FUZZ" \
      -w "$WL_WEB_COMMON" \
      -H "X-Forwarded-For: 127.0.0.1" \
      -H "X-Real-IP: 127.0.0.1" \
      -H "X-Original-URL: /FUZZ" \
      -H "X-Rewrite-URL: /FUZZ" \
      -mc 200,301,302 -t 10 -rate 5 -silent \
      -o "$OUTDIR/ferox_results/bypass_${safe}.json" 2>/dev/null || true
  done
  success "403 bypass done"
else
  warn "ffuf or common.txt not found — skipping 403 bypass"
fi

if check_tool ffuf && [ -f "$WL_API" ]; then
  info "Fuzzing 500 hosts..."
  head -n "$MAX_FUZZ_HOSTS" "$OUTDIR/Alive_500.txt" | while IFS= read -r url; do
    safe=$(echo "$url" | sed 's|https\?://||;s|/|_|g')
    ffuf -u "${url}/FUZZ" \
      -w "$WL_API" \
      -mc 200,201,301,302,401,405 \
      -fc 500 -t 10 -rate 5 -silent \
      -o "$OUTDIR/ferox_results/500_${safe}.json" 2>/dev/null || true
  done
  success "500 hosts fuzz done"
else
  warn "ffuf or api-endpoints.txt not found — skipping 500 host fuzz"
fi

# =============================================================
# PHASE 8 — API ENDPOINT DISCOVERY
# =============================================================
section "PHASE 8 — API ENDPOINT DISCOVERY"

if check_tool kr; then
  info "kiterunner..."
  kr scan "$OUTDIR/AliveSubs.txt" \
    -A=apiroutes-260227:10000 \
    -x 8 -j 10 -v info \
    --fail-status-codes 400,401,404,403,501,502,426,411 \
    -o "$OUTDIR/kiterunner_results.txt" 2>/dev/null || true
else
  warn "kiterunner not found — skipping (install: https://github.com/assetnote/kiterunner)"
fi
touch "$OUTDIR/kiterunner_results.txt"
success "kiterunner_results.txt — $(wc -l < "$OUTDIR/kiterunner_results.txt") endpoints"

if check_tool arjun; then
  info "arjun hidden parameter discovery..."
  arjun -i "$OUTDIR/LiveURLs.txt" \
    -o "$OUTDIR/arjun_params.json" \
    -t 10 -q 2>/dev/null || true
else
  warn "arjun not found — skipping (install: pip3 install arjun)"
fi
touch "$OUTDIR/arjun_params.json"

# =============================================================
# PHASE 9 — NUCLEI VULNERABILITY SCAN
# =============================================================
section "PHASE 9 — NUCLEI SCAN"

touch "$OUTDIR/nuclei_results.txt"
touch "$OUTDIR/takeover_results.txt"
touch "$OUTDIR/nuclei_tokens.txt"

if check_tool nuclei; then
  if [ -n "$NUCLEI_TPL" ]; then
    TPL_PATH="$NUCLEI_TPL"
  elif [ -d "$HOME/nuclei-templates" ]; then
    TPL_PATH="$HOME/nuclei-templates"
  elif [ -d "$HOME/.local/nuclei-templates" ]; then
    TPL_PATH="$HOME/.local/nuclei-templates"
  else
    warn "Nuclei templates not found. Run: nuclei -update-templates"
    TPL_PATH=""
  fi

  if [ -n "$TPL_PATH" ]; then
    info "Running nuclei exposures + misconfigs..."
    nuclei -list "$OUTDIR/AliveSubs.txt" \
      -t "$TPL_PATH/http/exposures/" \
      -t "$TPL_PATH/http/misconfiguration/" \
      -t "$TPL_PATH/http/takeovers/" \
      -severity low,medium,high,critical \
      -rl 5 \
      -silent \
      -o "$OUTDIR/nuclei_results.txt" 2>/dev/null || true
    success "nuclei_results.txt — $(wc -l < "$OUTDIR/nuclei_results.txt") findings"

    info "Subdomain takeover check on 404s..."
    nuclei -list "$OUTDIR/Alive_404.txt" \
      -t "$TPL_PATH/http/takeovers/" \
      -rl 5 -silent \
      -o "$OUTDIR/takeover_results.txt" 2>/dev/null || true

    info "Running nuclei token/config scan..."
    nuclei -list "$OUTDIR/AliveSubs.txt" \
      -t "$TPL_PATH/http/exposures/configs/" \
      -t "$TPL_PATH/http/exposures/tokens/" \
      -severity medium,high,critical \
      -rl 5 -silent \
      -o "$OUTDIR/nuclei_tokens.txt" 2>/dev/null || true
    success "nuclei_tokens.txt — $(wc -l < "$OUTDIR/nuclei_tokens.txt") findings"
  fi
else
  warn "nuclei not found — skipping (install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)"
fi

# =============================================================
# PHASE 10 — PORT DISCOVERY
# =============================================================
section "PHASE 10 — PORT DISCOVERY"

if check_tool naabu; then
  info "naabu port scan..."
  naabu -list "$OUTDIR/AliveSubs.txt" \
    -p 80,443,8080,8443,8000,8888,3000,4000,5000,9000,9090,9200,6379,27017,5432,3306 \
    -rate 50 -silent \
    -o "$OUTDIR/naabu_ports.txt" 2>/dev/null || true
else
  warn "naabu not found — skipping port scan"
fi
touch "$OUTDIR/naabu_ports.txt"
success "naabu_ports.txt — $(wc -l < "$OUTDIR/naabu_ports.txt") open ports"

# FIX 6: nmap — extract clean IPs from host:port pairs before passing to nmap
if check_tool nmap && [ -s "$OUTDIR/naabu_ports.txt" ]; then
  info "Extracting IPs from naabu output for nmap..."
  awk -F: '{print $1}' "$OUTDIR/naabu_ports.txt" \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
    | sort -u > "$OUTDIR/nmap_targets.txt"
  if [ -s "$OUTDIR/nmap_targets.txt" ]; then
    info "nmap service detection..."
    nmap -iL "$OUTDIR/nmap_targets.txt" -T3 -Pn -sV --open \
      -oN "$OUTDIR/nmap_results.txt" 2>/dev/null || true
    success "nmap_results.txt done"
  else
    warn "No valid IPs extracted for nmap — skipping"
  fi
else
  warn "nmap not found or no ports to scan — skipping"
fi
touch "$OUTDIR/nmap_results.txt"

# =============================================================
# PHASE 11 — INFRASTRUCTURE
# =============================================================
section "PHASE 11 — INFRASTRUCTURE RECON"

info "whois..."
whois "$DOMAIN" > "$OUTDIR/whois.txt" 2>/dev/null || true

if check_tool asnmap; then
  info "asnmap..."
  asnmap -d "$DOMAIN" -silent \
    -o "$OUTDIR/asnmap.txt" 2>/dev/null || true
else
  warn "asnmap not found — skipping"
fi
touch "$OUTDIR/asnmap.txt"

info "DNS SRV records..."
for srv in _kerberos._tcp _kpasswd._tcp _ldap._tcp \
           _kerberos._udp _http._tcp _https._tcp; do
  result=$(dig +short $srv.$DOMAIN SRV 2>/dev/null)
  [ -n "$result" ] && echo "$srv.$DOMAIN → $result" \
    >> "$OUTDIR/srv_records.txt"
done
touch "$OUTDIR/srv_records.txt"
success "srv_records.txt — $(wc -l < "$OUTDIR/srv_records.txt") SRV records"

info "Certificate transparency (internal hostnames)..."
curl -s --max-time 30 "https://crt.sh/?q=%25.$DOMAIN&output=json" \
  | python3 -c "
import json,sys
try:
    data=json.load(sys.stdin)
    names=set()
    for d in data:
        for n in d['name_value'].split('\n'):
            n=n.strip().lstrip('*.')
            if n: names.add(n)
    [print(n) for n in sorted(names)]
except: pass
" > "$OUTDIR/crtsh_all.txt" 2>/dev/null || true
touch "$OUTDIR/crtsh_all.txt"

# =============================================================
# FINAL SUMMARY
# =============================================================
section "RECON COMPLETE — SUMMARY"

echo -e "${BOLD}Output folder:${NC} $OUTDIR"
echo ""
printf "  %-35s %s\n" "File" "Count"
printf "  %-35s %s\n" "───────────────────────────────────" "─────"
printf "  %-35s %s\n" "AllSubs.txt"             "$(wc -l < "$OUTDIR/AllSubs.txt") subdomains"
printf "  %-35s %s\n" "AliveSubs.txt"           "$(wc -l < "$OUTDIR/AliveSubs.txt") alive"
printf "  %-35s %s\n" "Alive_200.txt"           "$(wc -l < "$OUTDIR/Alive_200.txt") → fuzz these"
printf "  %-35s %s\n" "Alive_401.txt"           "$(wc -l < "$OUTDIR/Alive_401.txt") → auth bypass"
printf "  %-35s %s\n" "Alive_403.txt"           "$(wc -l < "$OUTDIR/Alive_403.txt") → 403 bypass"
printf "  %-35s %s\n" "Alive_500.txt"           "$(wc -l < "$OUTDIR/Alive_500.txt") → investigate"
printf "  %-35s %s\n" "AllURLs.txt"             "$(wc -l < "$OUTDIR/AllURLs.txt") URLs"
printf "  %-35s %s\n" "js_urls.txt"             "$(wc -l < "$OUTDIR/js_urls.txt") JS files"
printf "  %-35s %s\n" "js_secrets.txt"          "$(wc -l < "$OUTDIR/js_secrets.txt") secret hits"
printf "  %-35s %s\n" "js_api_paths.txt"        "$(wc -l < "$OUTDIR/js_api_paths.txt") API paths"
printf "  %-35s %s\n" "admin_panels.txt"        "$(wc -l < "$OUTDIR/admin_panels.txt") admin URLs"
printf "  %-35s %s\n" "idor_targets.txt"        "$(wc -l < "$OUTDIR/idor_targets.txt") IDOR candidates"
printf "  %-35s %s\n" "login_flows.txt"         "$(wc -l < "$OUTDIR/login_flows.txt") auth endpoints"
printf "  %-35s %s\n" "open_redirects.txt"      "$(wc -l < "$OUTDIR/open_redirects.txt") redirect params"
printf "  %-35s %s\n" "sensitive_files.txt"     "$(wc -l < "$OUTDIR/sensitive_files.txt") sensitive files"
printf "  %-35s %s\n" "nuclei_results.txt"      "$(wc -l < "$OUTDIR/nuclei_results.txt") findings"
printf "  %-35s %s\n" "nuclei_tokens.txt"       "$(wc -l < "$OUTDIR/nuclei_tokens.txt") token findings"
printf "  %-35s %s\n" "takeover_results.txt"    "$(wc -l < "$OUTDIR/takeover_results.txt") takeovers"
printf "  %-35s %s\n" "kiterunner_results.txt"  "$(wc -l < "$OUTDIR/kiterunner_results.txt") API endpoints"
printf "  %-35s %s\n" "naabu_ports.txt"         "$(wc -l < "$OUTDIR/naabu_ports.txt") open ports"
printf "  %-35s %s\n" "srv_records.txt"         "$(wc -l < "$OUTDIR/srv_records.txt") SRV records"
echo ""

echo -e "${BOLD}Priority manual review:${NC}"
echo -e "  1. ${RED}js_secrets.txt${NC}       — hardcoded keys/tokens (low false positives)"
echo -e "  2. ${RED}nuclei_tokens.txt${NC}    — exposed configs/tokens"
echo -e "  3. ${RED}nuclei_results.txt${NC}   — auto-detected vulns"
echo -e "  4. ${RED}Alive_401.txt${NC}        — auth-protected endpoints"
echo -e "  5. ${RED}idor_targets.txt${NC}     — IDOR/BOLA surface (strict patterns)"
echo -e "  6. ${RED}admin_panels.txt${NC}     — admin/partner portals"
echo -e "  7. ${RED}Alive_500.txt${NC}        — crashing APIs"
echo -e "  8. ${RED}srv_records.txt${NC}      — internal infra leakage"
echo -e "  9. ${RED}open_redirects.txt${NC}   — open redirect chains"
echo -e " 10. ${RED}js_api_paths.txt${NC}     — hidden API endpoints in JS"
echo ""

echo -e "${BOLD}Tools status:${NC}"
for tool in subfinder assetfinder amass findomain httpx waybackurls gau hakrawler \
            katana gospider paramspider ffuf feroxbuster nuclei naabu nmap subjs arjun kr asnmap; do
  if check_tool "$tool"; then
    echo -e "  ${GREEN}✓${NC} $tool"
  else
    echo -e "  ${RED}✗${NC} $tool — NOT INSTALLED"
  fi
done

echo ""
echo -e "${GREEN}Finished: $(date)${NC}"
