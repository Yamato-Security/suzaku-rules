# Temporary Sigma rules

This folder holds **temporary stand-ins** for upstream [SigmaHQ](https://github.com/SigmaHQ/sigma) cloud rules whose detection fields do not yet work with Suzaku.

## Why these exist

Some upstream Azure rules match on legacy field names (e.g. `properties.message`) that do not match the field format Suzaku reads (e.g. `operationName`, aligned to the Azure Event Hub format). [@fukusuket](https://github.com/fukusuket) corrected these fields in suzaku-rules #67 and submitted the same fixes back upstream (see PRs below).

The corrected rules originally lived under `sigma/azure/`, but that tree is **disposable**: the daily sync (`.github/workflows/update-sigmarule.yaml`) runs `rm -rf sigma/`, re-pulls fresh upstream rules, and then deletes every rule whose UUID is listed in [`config/filtered_sigma_rules.txt`](../../config/filtered_sigma_rules.txt). So the fixes were wiped on every sync. Hosting them here under `suzaku/` — which the sync never touches — keeps them working.

## How it stays conflict-free

- Suzaku **loads** these rules from `suzaku/` (their UUIDs are **not** in the tool's `config/azure_ignore_rule_list.txt`).
- The sync **deletes** the broken upstream copies from `sigma/` on every run (their UUIDs **are** in `config/filtered_sigma_rules.txt`), so there is never a duplicate UUID.

Rule content and UUIDs here are identical to suzaku-rules #67.

## Upstream PRs to watch

These are the SigmaHQ PRs that fix the fields upstream. **All were still open as of 2026-07** — check the links for current status:

| Upstream PR | Folder it fixes |
| --- | --- |
| [SigmaHQ/sigma#5987](https://github.com/SigmaHQ/sigma/pull/5987) | `activity_logs` — align detection fields to Event Hub format |
| [SigmaHQ/sigma#5992](https://github.com/SigmaHQ/sigma/pull/5992) | `signin_logs` — align detection fields to Event Hub format |
| [SigmaHQ/sigma#5993](https://github.com/SigmaHQ/sigma/pull/5993) | `audit_logs` — align detection fields to Event Hub format |
| [SigmaHQ/sigma#5990](https://github.com/SigmaHQ/sigma/pull/5990) | `signin_logs` — reorganize (placeholder/deprecated rules) |

## How to remove these once upstream lands

When an upstream PR above is merged and the fix has flowed into `sigma/azure/` via the daily sync:

1. Delete the corresponding rules from this folder.
2. Remove their UUID entries from [`config/filtered_sigma_rules.txt`](../../config/filtered_sigma_rules.txt) so the now-fixed upstream rules are no longer deleted during the sync and load normally instead.

Do both together so there is no gap where the detection stops loading.
