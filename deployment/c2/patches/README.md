# C2 deployment patches

Runtime `bf1f275-umat.2` uses the reachable upstream commit `bf1f275` and the
ordered `*.patch` files in this directory. The former GeoLite2 projection patch
is no longer present because that behavior is implemented by the pinned
upstream commit itself.

`0001-threatfox-offline-feed.patch` adds the format-aware importer, completeness
gate, documentation, and tests. The complete 22 MB CSV is stored as the compressed
`deployment/c2/feeds/threatfox.zip` asset. The installer verifies the archive
digest, extracts its sole `threatfox.csv` member offline, verifies the extracted
feed digest, and only then computes the effective-tree identity. This packaging
preserves every indicator while preventing credential-shaped malware IOCs from
being interpreted as repository secrets in loose source text.
