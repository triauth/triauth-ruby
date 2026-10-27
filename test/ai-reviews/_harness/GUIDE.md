# Review guide (read this before producing a review)

This is the harness specification for an AI security review of triauth-ruby. A review evaluates **one
scope** (the protocol as a whole, or one public API method) and is written to a single Markdown file.
You are normally invoked by `test/ai-reviews/_harness/run.rb` (`rake ai_review`), which passes you a scope and
then stamps the controlled metadata after you write — but the format below is authoritative either way.

## Procedure

1. **Pick a scope** (one from the table below). You are usually told which one.
2. **Read the code for that scope** — the "Primary source" files and "Also consider" files.
   Then read the [Best Practices and Security Considerations](../../../README.md#best-practices-and-security-considerations)
   section and the matching method section of [`../../../README.md`](../../../README.md), and the
   [trust model](https://www.triauth.org/protocol/trust-model), so your review is grounded in the intended security model.
3. **Follow the execution trace of any relevant methods** - so that you gain deep understanding of how it works.
4. **Read the existing review file** `test/ai-reviews/<agent>/<scope>.md` if it exists. You MUST
   follow the ID rule below, so the file updates in place and a finding that no longer applies leaves it.
5. **Write/update** `test/ai-reviews/<agent>/<scope>.md` using the format in the next section.
   Start from [`TEMPLATE.md`](TEMPLATE.md) if the file is new.
6. Do not peek into other scope and/or other agents' review files as they may interfere with your jugement.

## What a review looks for

1. The documented security model for the scope (the README sections and the trust model above) and whether
   the code enforces it: every check, limit, ordering and error path of the protocol.
2. **Language-specific hazards:** integer and float behavior, string encoding and normalization, exceptions
   escaping where an error result is expected, shared mutable state and thread safety, timing of comparisons,
   TLS verification defaults of the HTTP client, DNS library quirks.
3. **Dependency hygiene:** OpenSSL and the standard library used as their documentation prescribes; no deprecated
   or unsafe modes.

## File format

YAML frontmatter, then a `## Summary` and a `## Findings` section:

```yaml
---
model: Fable 5.1
model_id: claude-fable-5-1
scope: authenticate
lib_version: 1.0.0.beta.4
commit: 29a73fc
reviewed_at: 2026-10-27
status: warnings              # computed by the runner; warnings here = one open medium finding (AUTH-001)
summary: One-line verdict.    #   (the info finding AUTH-002 is [reviewed], so it is excluded)
next_id: 3                    # stamped by the runner: the number the next new finding takes
settings:
  effort: high
---
```

> **You only own `scope`, `status`, `summary`, and the `## Findings` body.**
> The runner overwrites `model`, `model_id`, `lib_version`, `commit`, `reviewed_at`, `next_id`, and `settings`
> with the exact values it ran you under. Fill them with best-effort placeholders; don't depend on them.

Body:

```markdown
# <Model> review — Triauth.<scope>

## Summary
A few sentences: overall posture and the headline concerns (or "no issues found").
Also state if the library is safe to use in mission-critical production systems (but do not take into account its beta status). 
If not, always add a CRITICAL finding with the reason behind it. 

## Findings

### [AUTH-001] [medium] Short, specific title
**Location:** `lib/triauth/api/authentication.rb` (add `:line` if useful)
**Description:** What the issue is and why it matters, in protocol/security terms.
**Recommendation:** What to change or verify.

### [AUTH-002] [info] [reviewed] Another finding
**Location:** `lib/triauth/challenge_response_flow.rb`
**Description:** ...
> **Human review (zz, 2026-10-27):** Acknowledged — by design, documented in the README. Accepted.
```

If you find nothing, set `status: good-to-go`, write a one-line `## Summary`, and leave `## Findings`
with a single line: `_No findings._`

## Finding heading grammar

`### [<ID>] [<severity>] [reviewed]? <title>`

- **`<ID>`** = `<PREFIX>-<NNN>`, zero-padded (e.g. `AUTH-003`). Prefixes per scope:
  `protocol`→`PROTO`, `authenticate`→`AUTH`, `check`→`CHECK`, `ping`→`PING`, `whois`→`WHOIS`,
  `attest`→`ATTEST`, `sign`→`SIGN`, `stamp`→`STAMP`, `verify`→`VERIFY`, `validate`→`VALID`.
- **`<severity>`** = one of `info`, `low`, `medium`, `high`, `critical`.
- **`[reviewed]`** = human sign-off marker — **never add or remove this yourself**, and never alter a
  finding that has it or its `> **Human review …**` note.
- **`**Engineer note:**`** under a finding is the maintainer's answer, with evidence, where a finding was
  judged wrong or by design — **never add, remove, or alter one yourself**. Keep it when you keep the finding,
  and answer it in the Description if you still disagree.

### ID rule (append-only numbers)
- Before writing, read the existing file: its finding IDs and its `next_id`.
- For an issue that already has an ID, **reuse that ID** and update its body/severity in place.
- For a genuinely new issue, allocate `<PREFIX>-<next_id>`, zero-padded, and the number after it for the
  next new issue.
- A finding that is **fixed**, or no longer applies, is **removed** from the list. Do not keep it as a
  closed entry, and never reuse its number: the runner re-stamps `next_id` from the highest number the
  file has carried and refuses a run that brings a retired number back.
- Never renumber an ID, and never remove or alter a `[reviewed]` finding or its human note: it records a
  human ruling, and the runner refuses a run that drops or changes one.

### Status rule
The file `status` is a rollup of the worst **open** (non-`[reviewed]`) finding. `run.rb` computes it
for you from the per-finding severities — you don't hand-set it. (If writing a review by hand, apply
the same table.)

| Worst open finding | `status` |
|--------------------|----------|
| `critical` or `high` | `fatal` |
| `medium` | `warnings` |
| `low`, `info`, or none | `good-to-go` |

- A `[reviewed]` finding is human-accepted and **excluded** from the rollup, so a `medium`-or-worse
  finding leaves the rollup once it is **fixed** (and removed from the list) or **reviewed-and-accepted**
  (mark `[reviewed]` with a note).
- Your job is just to get each finding's **severity** right; the runner derives `status` when it stamps
  the file. A human who later marks a finding `[reviewed]` applies the same table to `status` by hand.

## Scope → source files

| Scope | Primary source | Also consider |
|-------|----------------|---------------|
| `protocol` | `lib/triauth/signature.rb`, `lib/triauth/multi_signature.rb`, `lib/triauth/challenge.rb`, `lib/triauth/response.rb`, `lib/triauth/challenge_response_flow.rb` | `lib/triauth/resolvers/`, `lib/triauth/verifiers/`, `lib/triauth/helpers.rb`, `README.md` (Best Practices and Security Considerations) |
| `authenticate` | `lib/triauth/api/authentication.rb` | `lib/triauth/challenge_response_flow.rb`, `lib/triauth/signature.rb` |
| `check` | `lib/triauth/api/authentication.rb` | identity/DNS models in `lib/triauth/identity*.rb` |
| `ping` | `lib/triauth/api/authentication.rb` | `lib/triauth/signature.rb` |
| `whois` | `lib/triauth/api/identity.rb` | `lib/triauth/identity_keys.rb`, `lib/triauth/identity_domain.rb`, `lib/triauth/authentication_endpoint.rb` |
| `attest` | `lib/triauth/api/attestation.rb` | `lib/triauth/signature.rb`, `lib/triauth/verifiers/` |
| `sign` | `lib/triauth/api/signing.rb` | `lib/triauth/signature.rb` |
| `stamp` | `lib/triauth/api/signing.rb` | `lib/triauth/signature.rb` |
| `verify` | `lib/triauth/api/signing.rb` | `lib/triauth/multi_signature.rb`, `lib/triauth/verifiers/` |
| `validate` | `lib/triauth/api/validation.rb` | `lib/triauth/validator.rb`, `lib/triauth/protocol.rb` |
