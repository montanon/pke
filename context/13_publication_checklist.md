# Publication Checklist

Use this checklist before publishing the repository or modifying `/context`.

## PII review

Confirm there are no:

- real names,
- emails,
- phone numbers,
- addresses,
- exact GPS coordinates,
- faces,
- license plates,
- workplace identifiers,
- device serial numbers,
- IP addresses,
- Apple account identifiers,
- private team details.

## Secret review

Confirm there are no:

- private keys,
- signing keys,
- seed phrases,
- API tokens,
- JWTs,
- database URLs with credentials,
- Supabase or Firebase service keys,
- Apple certificates,
- provisioning profiles,
- `.env` files,
- SSH keys,
- deployment credentials.

## Media review

Confirm there are no:

- real evidence photos,
- real audio,
- real video,
- images with EXIF metadata,
- screenshots with identifiable data,
- files generated from actual sensitive events.

## Technical disclosure review

Confirm there are no:

- step-by-step exploit instructions,
- unresolved vulnerability details that materially increase abuse risk,
- private backend routes,
- private infrastructure diagrams,
- security bypass notes,
- internal incident plans.

## Abuse-risk review

Confirm the docs do not describe the product as:

- general encrypted storage,
- anonymous media vault,
- social network,
- public evidence feed,
- uncensorable media distribution.

Confirm the docs emphasize:

- live capture only,
- no arbitrary uploads,
- selective disclosure,
- report/freeze mechanism,
- explicit limitations,
- custody verification rather than truth verification.

## Example data review

All examples should use fake placeholders such as:

```text
snap_test_001
owner_test_public_key_001
sha256_test_hash_001
dev_test_signature_001
```

## Final review

Before publishing:

- run secret scanning,
- review diffs manually,
- inspect images and metadata,
- verify `.gitignore`,
- confirm no private notes were committed.
