# Verifying BSEAL release artifacts

Every BSEAL release is signed with [Sigstore cosign](https://docs.sigstore.dev/cosign/overview/)
keyless signing. No long-term private key is stored. Instead, each release CI
run obtains a short-lived certificate from the Sigstore Fulcio CA using a
GitHub Actions OIDC token. The signing event is permanently recorded in the
public Rekor transparency log.

Each artifact on the GitHub Releases page is accompanied by two companion files:

| File | Purpose |
|---|---|
| `<artifact>.sig` | Raw signature (base64) |
| `<artifact>.pem` | Short-lived Fulcio certificate (encodes the workflow identity) |

## Quick verification

1. **Install cosign** (one-time):

   ```bash
   # macOS
   brew install cosign

   # Linux
   curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
     -o cosign && chmod +x cosign && sudo mv cosign /usr/local/bin/

   # Windows (PowerShell, winget)
   winget install sigstore.cosign
   ```

2. **Download** the artifact plus its `.sig` and `.pem` companions from the
   GitHub Releases page.

3. **Verify**:

   ```bash
   cosign verify-blob \
     --certificate  bseal-<version>-linux-amd64.deb.pem \
     --signature    bseal-<version>-linux-amd64.deb.sig \
     --certificate-identity-regexp \
       "^https://github\.com/.*/\.github/workflows/release\.yml@refs/tags/" \
     --certificate-oidc-issuer \
       "https://token.actions.githubusercontent.com" \
     bseal-<version>-linux-amd64.deb
   ```

   On success cosign prints:

   ```
   Verified OK
   ```

   The `--certificate-identity-regexp` check ensures the artifact was signed by
   the `release.yml` workflow in this repository, not by any other GitHub
   Actions job or external party.

4. **Verify checksums** (optional second layer):

   ```bash
   sha256sum --check SHA256SUMS.txt
   ```

## What the signature proves

- The artifact was produced by the `release.yml` workflow in this repository.
- It was signed during a run triggered by a version tag (`refs/tags/v*`).
- The signing event timestamp is immutably recorded in the public Rekor log.
- No stored secret key is involved — a compromised repository secret alone
  cannot produce a valid signature for a different workflow or repository.

## What it does not prove

- Correctness of the code or absence of vulnerabilities.
- That the build is reproducible byte-for-byte (Linux builds are; Windows
  vcpkg builds are pinned but not yet bit-for-bit reproducible).
