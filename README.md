# 🔍 Subdomain Recon Pipeline v3.1

A saturation-driven recon pipeline for bug bounty hunters and penetration testers — from subdomain discovery through takeover checks, URL/param harvest, and attack-surface ranking.

> ⚠️ **For authorized testing only.** Only use this tool on systems you own or have explicit written permission to test. The author is not responsible for any misuse or damage caused by this tool.

---

## How It Works

The pipeline runs in a feedback loop until it reaches **saturation** — meaning no significant new subdomains are being discovered. After the discovery loop, v3.1 adds bounty-focused triage phases.

```
┌─────────────────────────────────────────────────────┐
│  Phase 1   Passive Collection                       │
│            subfinder -all, amass, chaos,            │
│            crt.sh, RapidDNS, HackerTarget, GitHub   │
│                        ↓                            │
│  Phase 3   Recursive Early (capped seed)            │
│                        ↓                            │
│  ┌─── LOOP until saturation ───────────────────┐    │
│  │  Phase 2   Resolve + Wildcard Filter        │    │
│  │  Phase 4   Permutation (alterx)             │    │
│  │  Phase 5   Bruteforce (iter 1 by default)   │    │
│  │  Phase 6   ASN + PTR Pivot (asnmap + dnsx)  │    │
│  │  Phase 7   TLS Scrape (tlsx)                │    │
│  └─────────────────────────────────────────────┘    │
│                        ↓                            │
│  Phase 9   httpx Enrich (title, tech, favicon)      │
│  Phase 10  Favicon Hash → Shodan/Censys queries     │
│  Phase 11  Cloud Asset Discovery (S3/Azure/GCP)     │
│  Phase 12  Extract Words → Final Permutation Pass   │
│  Phase 13  Takeover (CNAME + nuclei/subzy + hints)  │
│  Phase 14  URL / Param Harvest (gau/wayback/katana) │
│  Phase 15  Rank Surface → ranked/interesting.txt    │
│  Phase 16  JSON Report                              │
└─────────────────────────────────────────────────────┘
```

**Termination condition:** new subdomains per iteration drops below threshold **OR** max iterations reached — whichever comes first.

**Hunt next:** open `ranked/interesting.txt` after a run.

---

## What's new in v3.1

- Subdomain takeover checks (`dnsx` CNAMEs, `nuclei -tags takeover`, `subzy`, dangling-provider hints)
- URL / param harvest (`gau`, `waybackurls`, capped `katana`)
- Attack-surface ranking so `dev` / `staging` / `admin` / `api` / `login` rise to the top
- Recursive early capped (default 150) to avoid O(n) blowups
- Full bruteforce only on iteration 1 by default (`--full-brute` to force every loop)
- Parallel Azure/GCP bucket probes with a candidate cap

---

## Installation

```bash
git clone https://github.com/iammerrida-source/recon-pipeline
cd recon-pipeline
chmod +x install.sh recon_pipeline.sh
./install.sh
```

### Manual dependency install

<details>
<summary>Required tools</summary>

```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
```
</details>

<details>
<summary>Optional tools (more coverage + v3.1 phases)</summary>

```bash
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/gwen001/github-subdomains@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/anew@latest
go install github.com/PentestPad/subzy@latest
pip3 install s3scanner uro dnsvalidator
nuclei -update-templates
```
</details>

### Wordlist

The pipeline uses the [jhaddix all.txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056) wordlist by default:

```bash
mkdir -p ~/tools/wordlists
wget -O ~/tools/wordlists/all.txt \
  https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/all.txt
```

### Resolvers

```bash
wget -O ~/tools/resolvers.txt \
  https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
```

---

## Usage

### Single domain
```bash
./recon_pipeline.sh -d example.com
```

### Scope file (multi-domain + exclusions)
```bash
./recon_pipeline.sh -s scope.txt
```

### Resume an interrupted run
```bash
./recon_pipeline.sh -d example.com -o recon_example_com_20260101 --resume
```

### All options
```
-d  target domain
-s  scope file
-o  output directory       (default: recon_<domain>_<timestamp>)
-w  wordlist path          (default: ~/tools/wordlists/all.txt)
-r  resolvers file         (default: ~/tools/resolvers.txt)
-t  threads                (default: 100)
-T  new-subs threshold     (default: 10)
-I  max iterations         (default: 5)
-R  rate limit (rps)       (default: 500)
    --resume               resume from last checkpoint
    --no-cloud             skip cloud asset discovery
    --no-github            skip GitHub enumeration
    --no-takeover          skip takeover checks
    --no-urls              skip URL / param harvest
    --no-rank              skip attack-surface ranking
    --full-brute           bruteforce every loop iteration
```

---

## Scope File Format

```
# In-scope domains
example.com
*.example.com

# Another domain
api.example.org

# Exclusions (prefix with !)
!staging.example.com
!internal.example.com
```

---

## Output Structure

```
recon_example_com_<timestamp>/
├── all_subdomains.txt
├── resolved.txt
├── live_urls.txt
├── permutation_words.txt
├── stats.json
├── valid_resolvers.txt
├── passive/
├── resolve/
├── permutation/
├── bruteforce/
├── asn/
├── tls/
├── httpx/
│   ├── enriched.txt
│   ├── favicon_hashes.txt
│   ├── shodan_queries.txt
│   └── censys_queries.txt
├── cloud/
├── takeover/
│   ├── findings.txt
│   ├── cnames.txt
│   └── dangling_cname_hints.txt
├── urls/
│   ├── all_urls.txt
│   ├── params.txt
│   └── param_names.txt
├── ranked/
│   ├── interesting.txt          ← start manual hunting here
│   ├── ranked_hosts.txt
│   ├── ranked_urls.txt
│   └── priority_hosts_top100.txt
├── words/
└── pipeline.log
```

---

## Example Output

```
╔══════════════════════════════════════════╗
║      PIPELINE COMPLETE                  ║
╚══════════════════════════════════════════╝
  Target(s):           example.com
  Total Subdomains:    1842
  Resolved / Live:     934
  Web Endpoints:       621
  Takeover Hits:       2
  URLs Harvested:      18440
  Interesting:         96
  Word Bank:           2103 words
  Iterations:          3
  Duration:            0h 18m 05s
```

---

## Methodology

1. **Passive sources** cast a wide net without touching the target
2. **Wildcard detection** prevents false positives from polluting the results
3. **Permutation engine** generates intelligent candidates from discovered labels
4. **ASN + PTR pivot** finds subdomains that passive sources miss entirely
5. **TLS scraping** extracts SANs from certificates on discovered IPs
6. **Favicon hashing** surfaces hidden infrastructure sharing the same frontend
7. **Word bank feedback** — every iteration enriches the permutation dictionary
8. **Takeover triage** catches dangling DNS / known fingerprintable services
9. **URL harvest** pulls historical and crawled endpoints with parameters
10. **Ranking** pushes high-value hosts/URLs to the front of your manual queue

---

## Legal

This tool is intended for **authorized security testing only**.

- Only test systems you own or have explicit written permission to test
- Respect the scope defined by bug bounty programs
- The author assumes no liability for misuse

---

## Contributing

Pull requests welcome. Please open an issue first to discuss significant changes.
