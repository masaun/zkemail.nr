# DKIM Subdomain Verification Fix

## Problem
Email providers sometimes sign messages with a DKIM `d=` domain that is a subdomain of the `From` header domain, rather than an exact match.

**Example:** A message from `test-company@example.com` signed with `d=email.example.com` would fail verification because the exact-match check required `email.example.com === example.com`.

This repo's `./js` library depends on `verifyDKIMSignature` from the `@zk-email/helpers` npm package, which performs a strict `signingDomain === domainToVerifyDKIM` check internally (see [`tryVerifyDKIM`](https://github.com/zkemail/zk-email-verify/blob/main/packages/helpers/src/dkim/index.ts)) and throws `DKIM signature not found for domain X` on mismatch. Since `./js` does not vendor that package's source, the fix is applied locally as a wrapper rather than patching `node_modules`.

Reference: [masaun/zk-email-verify: SPECIFIC_SUBDOMAIN_CHECK.md](https://github.com/masaun/zk-email-verify/blob/specific-subdomain-check/packages/helpers/doc/SPECIFIC_SUBDOMAIN_CHECK.md)

## Changed Functions
Both in [`js/src/index.ts`](../src/index.ts):

- `verifyDKIMSignature()`
- `generateEmailVerifierInputsFromDKIMResult()`

## The Fix

### `verifyDKIMSignature()`
No longer a passthrough re-export of `@zk-email/helpers`'s `verifyDKIMSignature`. It now calls the upstream implementation first, and if that throws `DKIM signature not found for domain X`, retries once with `email.X`:

```ts
export async function verifyDKIMSignature(
  email: Buffer | string,
  domain: string = "",
  enableSanitization: boolean = true,
  fallbackToZKEmailDNSArchive: boolean = false,
  skipBodyHash: boolean = false
): Promise<DKIMVerificationResult> {
  try {
    return await verifyDKIMSignatureUpstream(email, domain, enableSanitization, fallbackToZKEmailDNSArchive, skipBodyHash);
  } catch (err) {
    const notFoundMatch =
      err instanceof Error && err.message.match(/^DKIM signature not found for domain (.+)$/);
    if (!notFoundMatch) throw err;

    const failedDomain = notFoundMatch[1];
    if (failedDomain.startsWith("email.")) throw err;

    return await verifyDKIMSignatureUpstream(
      email,
      `email.${failedDomain}`,
      enableSanitization,
      fallbackToZKEmailDNSArchive,
      skipBodyHash
    );
  }
}
```

`skipBodyHash` is forwarded straight through to `@zk-email/helpers`'s `verifyDKIMSignature` (added upstream in `@zk-email/helpers@6.4.2`, hence the `js/package.json` bump from `^6.3.2`) — this wrapper previously declared only 4 params and dropped the 5th argument on both call sites, so callers had no way to reach it.

### `generateEmailVerifierInputsFromDKIMResult()`
This function accepts an already-verified `DKIMVerificationResult` directly, so callers who fetch or cache a DKIM result independently of `verifyDKIMSignature` had no domain guarantee at all. An optional `expectedDomain` field was added to `InputGenerationArgs` to close that gap:

```ts
if (params.expectedDomain) {
  const emailSubdomain = `email.${params.expectedDomain}`;
  if (signingDomain !== params.expectedDomain && signingDomain !== emailSubdomain) {
    throw new Error(
      `DKIM signing domain "${signingDomain}" does not match expected domain "${params.expectedDomain}" (or its "email." subdomain)`
    );
  }
}
```

This check runs before circuit inputs (including `pubkey.modulus`/`pubkey.redc`) are derived, so it does not affect their computation — both are still returned as before when `expectedDomain` is unset or matches.

## Security Consideration
Both checks use strict string equality (`===`), not pattern matching like `endsWith()`. This prevents domain-alignment bypasses by accepting **only** the literal `"email."` prefix, rejecting alternatives like `mail.example.com` or `notemail.example.com`.
