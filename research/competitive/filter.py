"""Filter the scraped inventory down to genuine SIH26164 competitors and rank them.

The raw scrape deliberately over-collects (349 repos across 24 queries) because topic tags are
applied inconsistently. This scores each repo for relevance to the four brief requirements and
writes shortlist.csv, so the manual analysis below is spent on real competitors.
"""
import csv
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

# Signals for the four brief requirements + the Phase-1 differentiators.
SIGNALS = {
    "cbom": [r"\bcbom\b", r"cryptographic bill of materials", r"crypto-?bom", r"cryptoassets"],
    "discovery": [r"discover", r"inventory", r"scanner", r"scanning", r"detect", r"static analysis",
                  r"sbom", r"dependency graph", r"attest"],
    "quantum_risk": [r"post-?quantum", r"\bpqc\b", r"quantum-safe", r"quantum threat", r"crqc",
                     r"harvest now", r"store now", r"mosca", r"ml-kem", r"kyber", r"ml-dsa",
                     r"dilithium", r"sphincs", r"fn-dsa", r"cryptograph", r"cryptanalysis"],
    "migration": [r"migrat", r"readiness", r"roadmap", r"transition", r"agil", r"upgrade"],
    "standards": [r"cyclonedx", r"spdx", r"nist", r"cnsa", r"fips 20[345]", r"ir 8547",
                  r"eccc", r"rfc 9180", r"hybrid"],
    "product": [r"dashboard", r"gui", r"web ui", r"report", r"api", r"cli", r"grype", r"vuln"],
}

NEGATIVE = [r"awesome-", r"tutorial", r"course", r"book", r"blog", r"interview", r"roadmap-",
            r"awesome", r"cheat", r"notes", r"slides", r"paper", r"survey", r"list of",
            r"awesome-l", r"defi", r"cryptocurrency", r"wallet", r"trading", r"coin", r"nft",
            r"blockchain", r"quantum-computing-(cirq|algorithms)", r"\bmath\b", r"learning",
            r"hacking", r"ctf", r"exploit", r"malware", r"ransomware", r"cryptanalysis-lab"]


def score(row):
    blob = " ".join([row.get("repo") or "", row.get("description") or "", row.get("topics") or ""]).lower()
    if any(re.search(n, blob) for n in NEGATIVE):
        return 0, 0
    hits = {}
    total = 0
    for key, pats in SIGNALS.items():
        n = sum(1 for p in pats if re.search(p, blob))
        hits[key] = n
        total += n
    stars = int(row.get("stars") or 0)
    # Relevance dominates; stars only break ties and mildly reward proven work.
    return total, stars


def main():
    rows = list(csv.DictReader(open(os.path.join(HERE, "inventory.csv"), encoding="utf-8")))
    scored = []
    for r in rows:
        rel, stars = score(r)
        r["relevance"] = rel
        r["stars_i"] = stars
        scored.append(r)
    scored = [r for r in scored if r["relevance"] >= 4]
    scored.sort(key=lambda r: (-r["relevance"], -r["stars_i"]))

    with open(os.path.join(HERE, "shortlist.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(scored[0].keys()))
        w.writeheader()
        w.writerows(scored)

    print(f"{len(rows)} scraped -> {len(scored)} shortlisted (relevance >= 4)\n")
    for r in scored[:32]:
        print(f"{r['relevance']:>3} {r['stars_i']:>6}  {r['repo'][:46]:<46} "
              f"{(r['description'] or '')[:72]}")


if __name__ == "__main__":
    main()
