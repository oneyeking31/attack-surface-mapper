# attack-surface-mapper
recon.sh — Automated Bug Bounty Recon Pipeline
A modular, rate-limited reconnaissance script for bug bounty and penetration testing engagements. Runs 11 phases of automated recon against a target domain and produces structured, actionable output files.

Legal notice: Only use against targets you have explicit written permission to test, or against programs in scope on platforms such as HackerOne, Bugcrowd, or Intigriti.


Features

11 automated phases — subdomain enum, alive detection, URL discovery, JS secret extraction, dir fuzzing, API discovery, Nuclei scanning, port scanning, and infrastructure recon
Graceful degradation — checks for every tool before calling it; skips with install hint if missing, never crashes
Low false positives — smart JS secret patterns with placeholder filtering; tight IDOR regex that excludes timestamps, cache params, and API version strings
Rate-limited — 5 req/sec across all tools by default, safe for bug bounty programs
Status-code bucketing — splits alive hosts into Alive_200, Alive_401, Alive_403, Alive_500 for immediate prioritisation
Parallel JS download — xargs -P 10 for fast concurrent file fetching
Auto-detects — SecLists path (both Kali variants), Nuclei templates, paramspider output format


Output files
FileWhat it containsAllSubs.txtAll unique subdomains foundAliveSubs.txtSubdomains responding to HTTP/SAlive_200/401/403/500.txtHosts bucketed by status codejs_secrets.txtHardcoded API keys, tokens, passwordsidor_targets.txtIDOR/BOLA candidates (strict patterns)admin_panels.txtAdmin, dashboard, internal URLsnuclei_results.txtNuclei-detected vulnerabilitiesnuclei_tokens.txtExposed config/token filestakeover_results.txtSubdomain takeover candidateskiterunner_results.txtAPI endpoint brute-force resultsnaabu_ports.txtOpen portsnmap_results.txtService/version detectionsrv_records.txtInternal infra leakage via DNS SRV

Installation
Required
bash# System tools
sudo apt install curl jq whois dnsutils

# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install github.com/tomnomnom/waybackurls@latest

# Python tools
pip3 install arjun paramspider

# Wordlists
sudo apt install seclists

# Nuclei templates
nuclei -update-templates
Optional (increases coverage)
bashgo install github.com/jaeles-project/gospider@latest
go install github.com/lc/subjs@latest
go install github.com/Findomain/Findomain@latest
sudo apt install amass ffuf feroxbuster nmap

# Kiterunner
wget https://github.com/assetnote/kiterunner/releases/latest/download/kr_linux_amd64.tar.gz
tar xf kr_linux_amd64.tar.gz && sudo mv kr /usr/local/bin/

Usage
bashchmod +x recon.sh
./recon.sh example.com
Output is saved to ~/recon_<domain>_<timestamp>/.
Optional API keys (for increased subdomain coverage)
Edit the top of the script:
bashGITHUB_TOKEN="your_token_here"     # github-subdomains
PDCP_API_KEY="your_key_here"       # chaos
Adjusting fuzzing scope
bashMAX_FUZZ_HOSTS=20   # default — increase for deeper coverage

Phase overview
Phase 1  — Subdomain enumeration (subfinder, assetfinder, amass, findomain, crt.sh, puredns, ffuf, vhosts)
Phase 2  — Merge & deduplicate
Phase 3  — Alive host detection + status code bucketing (httpx)
Phase 4  — URL discovery (waybackurls, gau, hakrawler, katana, gospider, paramspider)
Phase 5  — JavaScript secret extraction (parallel download + smart regex)
Phase 6  — Sensitive file discovery (wayback machine)
Phase 7  — Directory & 403 bypass fuzzing (feroxbuster, ffuf)
Phase 8  — API endpoint discovery (kiterunner, arjun)
Phase 9  — Vulnerability scanning (nuclei: exposures, misconfigs, takeovers, tokens)
Phase 10 — Port discovery + service detection (naabu, nmap)
Phase 11 — Infrastructure recon (whois, asnmap, DNS SRV, crt.sh)

Priority review order
After the scan completes, review output files in this order:

js_secrets.txt — hardcoded keys/tokens
nuclei_tokens.txt — exposed configs/tokens
nuclei_results.txt — auto-detected vulns
Alive_401.txt — auth bypass candidates
idor_targets.txt — IDOR/BOLA surface
admin_panels.txt — admin/partner portals
Alive_500.txt — crashing endpoints
srv_records.txt — internal infra leakage
open_redirects.txt — open redirect chains
js_api_paths.txt — hidden API endpoints


Tested on

Kali Linux 2024.x
Ubuntu 22.04 / 24.04


Author
Salah Khantar — Cybersecurity Engineering student at ESIEE Paris
LinkedIn · TryHackMe
