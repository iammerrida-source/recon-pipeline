# 🔍 Subdomain Recon Pipeline

A fast, modular, and saturation-driven subdomain discovery pipeline for bug bounty hunters and penetration testers.

> ⚠️ **For authorized testing only.** Only use this tool on systems you own or have explicit written permission to test. The author is not responsible for any misuse or damage caused by this tool.

---

## How It Works

The pipeline runs in a feedback loop until it reaches **saturation** — meaning no significant new subdomains are being discovered. Each iteration builds on the previous one.

```
┌─────────────────────────────────────────────────────┐
│  Phase 1   Passive Collection                       │
│            subfinder -all, amass, chaos,            │
│            crt.sh, RapidDNS, HackerTarget, GitHub   │
│                        ↓                            │
│  Phase 3   Recursive Early (subfinder)              │
│                        ↓                            │
│  ┌─── LOOP until saturation ───────────────────┐    │
│  │  Phase 2   Resolve + Wildcard Filter        │    │
│  │  Phase 4   Permutation (alterx)             │    │
│  │  Phase 5   Bruteforce (shuffledns)          │    │
│  │  Phase 6   ASN + PTR Pivot (asnmap + dnsx)  │    │
│  │  Phase 7   TLS Scrape (tlsx)                │    │
│  └─────────────────────────────────────────────┘    │
│                        ↓                            │
│  Phase 9   httpx Enrich (title, tech, favicon)      │
│  Phase 10  Favicon Hash → Shodan/Censys queries     │
│  Phase 11  Cloud Asset Discovery (S3/Azure/GCP)     │
│  Phase 12  Extract Words → Final Permutation Pass   │
│  Phase 13  JSON Report                              │
└─────────────────────────────────────────────────────┘
```

**Termination condition:** new subdomains per iteration drops below threshold **OR** max iterations reached — whichever comes first.

---

## Installation

```bash
git clone https://github.com/iammerida/recon-pipeline
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
<summary>Optional tools (more coverage)</summary>

```bash
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/gwen001/github-subdomains@latest
pip3 install s3scanner
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
├── all_subdomains.txt        all discovered subdomains
├── resolved.txt              live hosts with resolved IPs
├── live_urls.txt             httpx enriched (title/tech/status/favicon)
├── permutation_words.txt     accumulated word bank
├── stats.json                machine-readable summary
├── valid_resolvers.txt       validated resolver list
├── passive/                  per-source passive results
├── resolve/                  per-iteration dnsx output
├── permutation/              alterx permutation candidates
├── bruteforce/               shuffledns bruteforce results
├── asn/                      ASN CIDR ranges + PTR results
├── tls/                      tlsx certificate SAN/CN data
├── httpx/
│   ├── enriched.txt          full httpx output
│   ├── favicon_hashes.txt    top favicon hashes
│   ├── shodan_queries.txt    ready-to-paste Shodan queries
│   └── censys_queries.txt    ready-to-paste Censys queries
├── cloud/
│   ├── s3_found.txt          exposed S3 buckets
│   ├── azure_found.txt       Azure blob storage hits
│   └── gcp_found.txt         GCP storage hits
└── pipeline.log              full execution log
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
  Word Bank:           2103 words
  Iterations:          3
  Duration:            0h 14m 22s
```

---

## Methodology

This pipeline implements a saturation-based discovery loop inspired by techniques used in real-world bug bounty recon:

1. **Passive sources** cast a wide net without touching the target
2. **Wildcard detection** prevents false positives from polluting the results
3. **Permutation engine** generates intelligent candidates from discovered labels
4. **ASN + PTR pivot** finds subdomains that passive sources miss entirely
5. **TLS scraping** extracts SANs from certificates on discovered IPs
6. **Favicon hashing** surfaces hidden infrastructure sharing the same frontend
7. **Word bank feedback** — every iteration enriches the permutation dictionary

---

## Legal

This tool is intended for **authorized security testing only**.

- Only test systems you own or have explicit written permission to test
- Respect the scope defined by bug bounty programs
- The author assumes no liability for misuse

---

## Contributing

Pull requests welcome. Please open an issue first to discuss significant changes.
