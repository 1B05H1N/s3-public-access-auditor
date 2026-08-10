# s3-public-access-auditor

Audit an S3 bucket configuration for public exposure - offline, from JSON you
export. Analyzes the bucket policy, ACL grants, and Public Access Block settings
for world-readable/writable access, unconditioned public principals, and missing
TLS-only enforcement. Pure Python standard library, no dependencies, no network
calls.

> **Goal:** catch the classic "public S3 bucket" and "no TLS-only policy" before
> it becomes a headline - in review or CI, from exported config.

## What it does

- Policy: flags `Principal:*` allows (public read = high, public write = critical), downgrades when a restricting `Condition` is present, and flags missing `aws:SecureTransport=false` deny
- ACL: flags grants to `AllUsers` / `AuthenticatedUsers`
- Public Access Block: flags any of the four settings not enabled
- Severity-ranked output, optional JSON, `--fail-on` for CI gating

## Files

- `s3_audit.py` - CLI and audit engine
- `samples/` - public (bad) and private (good) example configs
- `test_s3_audit.py` - unit tests

## Input

Either a bare bucket policy (has `Statement`) or a wrapper:

```json
{"policy": {...}, "acl": {"grants": [...]}, "public_access_block": {...}}
```

## Usage

```bash
python3 s3_audit.py samples/public-bucket.json
python3 s3_audit.py samples/private-bucket.json --fail-on medium
```

## Test

```bash
python3 -m unittest -v
```

## Disclaimer

This repository reflects personal study and practice; samples are synthetic and
contain no account data. It analyzes exported config only. Provided as-is;
validate against your own context.

## License

MIT. See [LICENSE](LICENSE).
