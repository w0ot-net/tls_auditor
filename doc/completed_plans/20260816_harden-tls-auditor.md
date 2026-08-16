# Plan: Harden and Document the TLS Auditor

*Distilled: 2026-08-16*

## Summary

Make the existing single-file CLI trustworthy and presentable without turning it
into a package or framework. Correct the protocol policy and target parsing,
preserve each requested host/port pairing during scans, make temporary-file
handling collision-safe, remove the small amount of duplicated merge logic, and
document the resulting behavior. Add one compact standard-library test module
covering only these high-risk transformations.

## Problem

The repository is clean and the CLI is easy to invoke, but several behaviors can
produce inaccurate or surprising audit results. TLS 1.1 is not treated as a
deprecated protocol, bracketed IPv6 endpoints with explicit ports are parsed
incorrectly, and rich/host-port inputs are converted to a Cartesian product of
all hosts and all ports instead of retaining the supplied pairs. Temporary host
files use predictable names and are not cleaned on every exit path. The script
also advertises Python 3.6 even though it uses Python 3.8-era APIs, duplicates its
result-merging algorithm, and contains substantial trailing whitespace.

The README currently contains one unrelated sentence, so users have no reliable
description of prerequisites, input contracts, security policy, outputs, or
operational limitations. There are no regression tests for the parsing and
aggregation code that determines the audit findings.

## Scope

In scope:

- Treat SSLv2, SSLv3, TLS 1.0, and TLS 1.1 as deprecated protocols whose
  presence is reported as `All`, following RFC 8996 for TLS 1.0 and TLS 1.1.
- Parse bare hosts, IPv4/hostname ports, and bracketed IPv6 ports consistently;
  recognize those forms during input-format detection, and keep the existing
  mixed-input behavior where a bare host in host-port mode defaults to port 443.
- Preserve the exact host/port relationships supplied in rich and host-port
  inputs by grouping scan jobs by port instead of applying the union of ports
  to every host.
- Keep simple input behavior unchanged: `-p` remains a global port list for
  every host in that input format.
- Give every scan job/round a unique XML path, aggregate all successful XML
  results, and fail clearly if any requested port group has no successful round
  rather than silently presenting partial coverage as complete.
- Treat unreadable or malformed Nmap XML as an audit failure, including in
  `--xml` mode, rather than reporting it as a clean result.
- Use the standard library's secure temporary-directory/file facilities and
  guaranteed cleanup for generated host lists, including failure paths.
- Consolidate the duplicated per-protocol row merge behavior behind one small
  helper shared by XML-round aggregation and CSV merging.
- Correct the documented minimum runtime to Python 3.8+, remove unused imports
  and trailing whitespace, and retain the current single-script architecture.
- Replace the README with concise installation, authorization, input-format,
  command, output, policy, XML-retention, and limitation documentation.
- Add a minimal `.gitignore` for Python/test caches and one `unittest` module
  with focused regression coverage.

Out of scope:

- Splitting the script into a package, publishing it, or adding `pyproject.toml`
  and dependency-management machinery.
- CI services, coverage gates, lint/format frameworks, or third-party testing
  dependencies.
- A changelog, release/versioning system, or license selection; the latter
  requires an explicit owner choice.
- Redesigning the output CSV schemas, adding new scan policies or CLI flags, or
  attempting to test Nmap itself.
- Live network scans as part of automated validation.

## Design

Keep `tls_auditor.py` as the sole production module and retain its existing CLI.
Extend `DEPRECATED_PROTOCOLS` with `TLSv1.1`; the existing XML parsing and
`format_ciphers` path should then report any observed TLS 1.1 support as `All`
without a second policy mechanism.

Use one host/port parser and the same explicit-port recognizer for input-format
detection, input endpoints, and CSV `Host:Port` values. This ensures a file
containing bracketed IPv6 endpoints reaches host-port parsing instead of being
misclassified as simple input. Bracketed IPv6 must be stored without brackets
internally, while formatting must continue to emit `[address]:port`. A final
numeric suffix is an explicit port only for a normal hostname/IPv4 form or a
bracketed IPv6 form; an unbracketed IPv6 literal remains a bare host and receives
port 443 in host-port mode. Invalid bracket/port forms should produce a clear
input error rather than being silently reinterpreted as a hostname.

Replace `build_nmap_targets`' global host/port union with scan jobs that each
contain a port and the deduplicated hosts explicitly assigned to that port. For
example, `a.example:443` plus `b.example:8443` produces two jobs, not scans of
both ports on both hosts. The simple `-i ... -p ...` path creates one job and
therefore keeps its intentional global-port semantics. Repeated host/port rows
remain deduplicated.

Execute every job for every requested round, using a `TemporaryDirectory` for
job-specific Nmap host files. Preserve the legacy XML name when there is one job
and one round; add deterministic port and/or round suffixes when more than one
XML file is needed. Track successes per job: one successful round is sufficient
for that job, but zero successful rounds for any job makes the command fail.
Parse or aggregate every successful XML file, even when multiple port groups
were scanned with `--rounds 1`. Existing `--keep-xml` behavior remains, with the
README documenting multi-file names; otherwise all generated XML files are
removed in a `finally` path. User-supplied `--xml` files are never removed.
Track attempted XML paths separately from successfully completed paths so failed
Nmap attempts are also cleaned. Let XML read/parse errors propagate to one CLI
error boundary; any invalid XML aborts output generation and returns nonzero,
while a valid XML document with no findings retains the current clean-result
behavior.

Extract the existing sentinel-aware merge rules (`-`, `All`, and normalized
cipher lists) into a helper that merges one result row into another. Both
`aggregate_results` and `merge_cipher_csvs` call it, keeping one definition of
the invariant and avoiding new classes or state containers.

Use `unittest`, `tempfile`, and `unittest.mock` only. Tests should exercise pure
helpers wherever possible and mock `run_nmap` only for the narrow orchestration
case needed to verify job separation and cleanup. Small inline XML/CSV fixtures
may be written under a temporary directory; no committed generated scan output
or fixture hierarchy is needed.

## Affected Components

- `tls_auditor.py`: update the deprecated-protocol policy, endpoint parsing,
  scan-job construction and orchestration, temporary/XML lifecycle, shared merge
  logic, runtime claim, and whitespace/import hygiene.
- `tests/test_tls_auditor.py`: add compact standard-library regression tests for
  input detection and endpoint parsing, TLS 1.1 classification/XML output,
  malformed XML failure, exact host/port grouping, sentinel-aware merging, and
  the relevant scan cleanup/failure invariant.
- `README.md`: replace the unrelated placeholder with the authoritative user
  guide and accurately describe the corrected behavior.
- `.gitignore`: ignore `__pycache__/`, compiled Python files, and local test
  caches so validation does not dirty the repository.

## Implementation Sequence

1. Add the shared endpoint parser/recognizer and focused tests for hostname,
   IPv4, bare IPv6, bracketed IPv6 detection, default-port, duplicate, and
   malformed input behavior; route format detection, host-port input, and CSV
   parsing through it without changing CSV output.
2. Add TLS 1.1 to the deprecated policy and test both direct classification and
   an inline Nmap XML example that must yield `TLSv1.1 = All`.
3. Replace the host/port union with port-grouped scan jobs, update XML naming and
   aggregation for multiple jobs/rounds, and put temporary and generated XML
   cleanup behind guaranteed lifecycle handling. Add a narrow mocked regression
   test proving that supplied pairs do not become a Cartesian product and that a
   wholly failed job is not reported as a complete audit.
4. Make XML read/parse errors fatal at the CLI boundary and cover malformed
   generated and user-supplied XML without conflating either with a valid scan
   that has no findings.
5. Extract and test the shared result-row merge helper, then use it from both XML
   aggregation and CSV merge paths.
6. Perform the bounded code-hygiene pass: state Python 3.8+, remove unused
   imports/trailing whitespace, and add the cache-only `.gitignore`.
7. Rewrite the README from the final CLI behavior, including prerequisites,
   permission warning, all three input formats, IPv6 notation, examples,
   generated files, deprecated/CBC/weak-cipher policy, multi-round behavior,
   and the fact that grouped rich inputs may invoke Nmap more than once.

## Validation

- Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`.
- Compile without writing bytecode:
  `python3 -c "from pathlib import Path; p = Path('tls_auditor.py'); compile(p.read_text(), str(p), 'exec')"`.
- Run `python3 tls_auditor.py --help` and compare its options/examples with the
  README.
- Run `git diff --check` and confirm no trailing whitespace remains in the
  touched files.
- Confirm test execution leaves no tracked or unignored generated artifacts
  with `git status --short`.
- Inspect the mocked Nmap calls to confirm `a:443` and `b:8443` never create a
  job containing both hosts and both ports.
- Do not run live Nmap scans without separately authorized targets.

## Success Criteria

- TLS 1.1 presence is always reported as deprecated, consistent with TLS 1.0.
- Hostname, IPv4, and bracketed IPv6 endpoint inputs round-trip to the correct
  `Host:Port` form and select the correct input mode, while malformed explicit
  endpoints fail clearly.
- Rich/host-port scans invoke Nmap only for supplied host/port pairs; simple
  inputs still scan their explicit global `-p` list.
- Multiple jobs and rounds have collision-free XML files, all successful results
  are aggregated, no requested port group can fail silently, and temporary files
  are removed on success and failure.
- Unreadable or malformed XML exits nonzero without producing clean-result CSVs;
  valid XML with no findings remains a successful empty audit.
- XML aggregation and CSV merging share one tested cipher-value merge rule.
- The README is sufficient to install and operate the tool without reading its
  source, and its Python/version and scan-behavior claims match the code.
- The focused standard-library tests and validation commands pass without
  adding third-party tooling or leaving generated artifacts.

## Execution Notes

Executed on 2026-08-16.

- Implemented shared endpoint parsing and port normalization, including mixed
  hostname/IPv4 input, bare IPv6, bracketed IPv6 ports, format detection, and
  CSV endpoint parsing.
- Added TLS 1.1 to the deprecated-protocol policy and retained `All` as the
  report value for every observed deprecated protocol.
- Replaced the host/port Cartesian product with exact port-grouped scan jobs,
  preserved the simple input mode's global `-p` behavior, added collision-free
  multi-job/round XML names, and required at least one successful round per job.
- Moved generated host lists into `TemporaryDirectory`, tracked every attempted
  XML path for cleanup, preserved `--keep-xml`, and left user-supplied XML
  untouched.
- Made unreadable or malformed XML fatal at the CLI boundary while preserving a
  successful no-findings result for valid empty scans.
- Consolidated XML aggregation and CSV merge semantics in `merge_result_row`.
- Replaced the README, added the cache-only `.gitignore`, removed trailing
  whitespace, and added one standard-library regression module with 16 tests.
- Changed only `.gitignore`, `README.md`, `tls_auditor.py`, and
  `tests/test_tls_auditor.py`; the tool remains a single production script.
- Material deviations: none. Numeric port validation/normalization is the
  direct implementation of the planned malformed-endpoint behavior.
- Validation passed:
  `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`, direct
  compilation, Python 3.8 grammar parsing, `python3 tls_auditor.py --help`,
  `git diff --check`, trailing-whitespace inspection, and generated-cache
  inspection.
- Implementation commit: `de97ec3` (`Harden TLS audit scanning and
  documentation`).
- Deliberately excluded work remains unchanged: packaging, CI, third-party
  tooling, module splitting, changelog/versioning, license selection, output
  schema redesign, and live network scans.
