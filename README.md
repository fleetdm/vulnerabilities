# Vulnerabilities

Vulnerabilities generates JSON feeds twice hourly by Fleet containing enriched CVEs matched to CPEs. Fleet servers use this information to identify vulnerable versions of software in Fleet's software inventory.

Every feed is attached to the `cve-*` release the [Generate CVE](.github/workflows/generate-cve.yml)
workflow cuts on each run. Fleet servers only read assets from the **latest** release, so a feed
that misses a run is simply absent from that release until the next one.

## Go vulnerability database artifact

The [Go vulnerability database](https://vuln.go.dev) — the data `govulncheck` uses — is mirrored
into one release asset per run. Fleet matches Go binaries (`software.source = 'go_binaries'`)
against it by module path, which a binary's name cannot give you. Mirroring keeps a single egress
point: Fleet servers never reach `vuln.go.dev` themselves.

Like the NVD and OSV feeds, both halves live in fleetdm/fleet and this workflow runs them:

| | |
| --- | --- |
| Generator | [`cmd/govulndb-mirror`](https://github.com/fleetdm/fleet/tree/main/cmd/govulndb-mirror) |
| Consumer | [`server/vulnerabilities/govulndb/`](https://github.com/fleetdm/fleet/tree/main/server/vulnerabilities/govulndb), added in Fleet 4.93.0 |

Both sides have to agree on the format below.

### Format

One gzipped JSON document per snapshot, named `govulndb-YYYY-MM-DD.json.gz`. Fleet takes the
lexically last matching asset on the latest release, so the name has to stay sortable.

```json
{
  "schema_version": "1",
  "generated": "2026-09-09T00:00:00Z",
  "modules": {
    "github.com/example/tool": [
      {
        "id": "GO-2024-1234",
        "cves": ["CVE-2024-1234"],
        "ranges": [{ "introduced": "0", "fixed": "1.49.0" }]
      }
    ],
    "stdlib": [
      {
        "id": "GO-2024-2963",
        "cves": ["CVE-2024-24791"],
        "ranges": [
          { "introduced": "0", "fixed": "1.21.12" },
          { "introduced": "1.22.0-0", "fixed": "1.22.5" }
        ]
      }
    ]
  }
}
```

- **Keys are module paths exactly as upstream reports them**, `/v2` suffixes and all, plus
  `stdlib`. Fleet compares them by exact string against the module path fleetd read out of the
  binary's build info, so neither side normalizes.
- **Versions carry no leading `v`** (`1.21.12`, not `v1.21.12`). Fleet strips and re-adds it.
- **`ranges` is half-open**: `introduced <= v < fixed`. An entry with no `fixed` has no fix yet.
  The publisher builds these by pairing each `introduced` in the upstream `events` list with the
  `fixed` that follows it.
- **`cves` holds only `CVE-` aliases.** A report whose aliases are all GHSA is not mirrored at
  all: `software_cve` and every CVE metadata join are keyed on a CVE ID, so it has nowhere to go.
- **`toolchain` is never emitted.** Those advisories affect the `go` command on the build machine,
  not the binary it produced.
- **Withdrawn reports are dropped.** Upstream leaves their ranges in place, and they are usually
  "every version, no fix", so publishing one flags every host running the module for an advisory
  its maintainers retracted.
- `schema_version` is `"1"`. Fleet's analyzer rejects any other value, so changing the format
  needs a new version *and* a Fleet release that reads it, shipped first.

No digest is published alongside: GitHub reports the asset digest itself, and Fleet verifies
against that.

### Why a run may publish nothing

Fleet reads a database with fewer advisories as those advisories having been **remediated**, and
deletes the matching `software_cve` rows. A partial or garbled snapshot would therefore clear real
vulnerabilities off customer hosts. So the publisher validates before it writes anything, and a
snapshot is held back when:

| Check | Tripped by |
| --- | --- |
| `modules` is empty, or carries no `stdlib` | a collection that went wrong upstream of any count |
| module or advisory count fell more than **5%** below the last published artifact | a bad upstream day; reports are withdrawn one at a time, never in batches |
| a fetch failed, or the archive is missing reports its own index names | a half-mirrored download |
| a report's `events` do not alternate introduced/fixed | a shape that cannot be paired without guessing, which would shift every bound |
| a range carries a `type` other than `SEMVER` | version ordering this publisher does not implement |

The threshold is `--max-drop-percent`, which defaults to 5%, and the workflow does not pass it —
widening it for a genuinely large withdrawal still means editing the generate step.

Turning the comparison off does not. A bad baseline blocks every run after it, and since each run
measures itself against the last published artifact, nothing clears that on its own. Dispatch
[Generate CVE](.github/workflows/generate-cve.yml) with **`govulndb_skip_drop_check`** checked and
the run takes no baseline at all, publishing whatever upstream hands over. It is deliberately
blunt: with the comparison off, nothing stands between a half-mirrored database and customer
hosts, and the artifact it publishes becomes the baseline every later run is measured against. The
`#help-engineering` alert fires on any run that publishes this way.

When a check trips the run **skips the publish, alerts `#help-engineering`, and exits zero** — a
bad upstream day should not page anyone, and it must not take the NVD and OSV artifacts down with
it. The release then carries no `govulndb-*` asset, Fleet's `Refresh` returns early without
deleting anything, and servers keep analyzing against the artifact already on disk. The failure
mode is stale data, not missing data.

That also means a publisher stuck in this state degrades silently: from the outside, weeks of
stale data look exactly like weeks of healthy runs. The Slack alert is the only thing that says
otherwise, so it fires on every run that skips this way and names the check that tripped and by
how much. A local failure instead — a broken flag, an unwritable output directory — exits
non-zero and turns the job red, which raises its own alarm.

### Running it locally

From a fleetdm/fleet checkout:

```bash
go test ./cmd/govulndb-mirror/...

# Write a snapshot without publishing anything. A baseline is mandatory, so say outright that
# there is none to compare against; otherwise the command exits 2.
cd cmd/govulndb-mirror
go run . --output /tmp/govulndb --first-run
gunzip -c /tmp/govulndb/govulndb-*.json.gz | jq '.modules["helm.sh/helm/v3"]'

# Exercise the drop check against an earlier snapshot.
go run . --output /tmp/govulndb --previous /tmp/govulndb-2026-09-16.json.gz
```

To see what upstream says about a module:

```bash
curl -s https://vuln.go.dev/index/modules.json | jq '.[] | select(.path=="helm.sh/helm/v3")'
curl -s https://vuln.go.dev/ID/GO-2022-0384.json | jq '{aliases, affected}'
```
