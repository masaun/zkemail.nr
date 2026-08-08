import {
  Uint8ArrayToCharArray,
  MAX_BODY_PADDED_BYTES,
  MAX_HEADER_PADDED_BYTES,
  generatePartialSHA,
  sha256Pad,
  findIndexInUint8Array,
} from "@zk-email/helpers";
import {
  DKIMVerificationResult,
  verifyDKIMSignature as verifyDKIMSignatureUpstream,
} from "@zk-email/helpers/dist/dkim";
import * as NoirBignum from "@mach-34/noir-bignum-paramgen";
import {
  u8ToU32,
  getHeaderSequence,
  getAddressHeaderSequence,
  Sequence,
  BoundedVec,
} from "./utils";

// This file is essentially https://github.com/zkemail/zk-email-verify/blob/main/packages/helpers/src/input-generators.ts
// modified for noir input generation

/**
 * @description Verify the DKIM signature of an email, retrying against the `email.` subdomain
 * convention some providers use (e.g. signing as `d=email.example.com` for a `From` domain of
 * `example.com`). @zk-email/helpers only exact-matches the signing domain, so those otherwise
 * valid emails would fail verification. See:
 * https://github.com/masaun/zk-email-verify/blob/specific-subdomain-check/packages/helpers/doc/SPECIFIC_SUBDOMAIN_CHECK.md
 * @param email Entire email data as a string or buffer
 * @param domain Domain to verify DKIM signature for. If not provided, the domain is extracted from the `From` header
 * @param enableSanitization If true, email will be applied with various sanitization to try and pass DKIM verification
 * @param fallbackToZKEmailDNSArchive If true, ZK Email DNS Archive (https://archive.prove.email/api-explorer) will
 *                                    be used to resolve DKIM public keys if we cannot resolve from HTTP DNS
 * @param skipBodyHash If true, bypass the DKIM body hash check
 */
export async function verifyDKIMSignature(
  email: Buffer | string,
  domain: string = "",
  enableSanitization: boolean = true,
  fallbackToZKEmailDNSArchive: boolean = false,
  skipBodyHash: boolean = false
): Promise<DKIMVerificationResult> {
  try {
    return await verifyDKIMSignatureUpstream(
      email,
      domain,
      enableSanitization,
      fallbackToZKEmailDNSArchive,
      skipBodyHash
    );
  } catch (err) {
    const notFoundMatch =
      err instanceof Error &&
      err.message.match(/^DKIM signature not found for domain (.+)$/);
    if (!notFoundMatch) throw err;

    // Only retry with the literal "email." prefix (not endsWith/pattern matching) to avoid
    // domain-alignment bypasses via lookalike subdomains like "notemail.example.com".
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

export type CircuitInput = {
  // required inputs for all zkemail verifications
  header: BoundedVec;
  pubkey: {
    modulus: string[];
    redc: string[];
  };
  signature: string[];
  dkim_header_sequence: Sequence;
  // inputs used for verifying full or partial hash
  body?: BoundedVec;
  body_hash_index?: string;
  // inputs used for only partial hash
  partial_body_real_length?: string;
  partial_body_hash?: string[];
  // inputs used for only masking
  header_mask?: string[];
  body_mask?: string[];
  // input for decoded body
  decoded_body?: BoundedVec;
  // inputs used for address extraction
  from_header_sequence?: Sequence;
  from_address_sequence?: Sequence;
  to_header_sequence?: Sequence;
  to_address_sequence?: Sequence;
};

export type InputGenerationArgs = {
  ignoreBodyHashCheck?: boolean;
  shaPrecomputeSelector?: string;
  maxHeadersLength?: number;
  maxBodyLength?: number;
  removeSoftLineBreaks?: boolean;
  headerMask?: number[];
  bodyMask?: number[];
  // todo: probably move these out into a separate extended type?
  extractFrom?: boolean;
  extractTo?: boolean;
  // if set, validates that the DKIM signing domain matches this domain (or its "email." subdomain)
  expectedDomain?: string;
};

/** Formatted for BoundedVec in case used in other places */
function removeSoftLineBreaks(body: BoundedVec): BoundedVec {
  const result = [];
  let i = 0;
  let count = 0;
  while (i < body.storage.length) {
    if (
      i + 2 < body.storage.length &&
      body.storage[i] === "61" && // '=' character
      body.storage[i + 1] === "13" && // '\r' character
      body.storage[i + 2] === "10"
    ) {
      // '\n' character
      // Skip the soft line break sequence
      i += 3; // Move past the soft line break
    } else {
      result.push(body.storage[i]);
      i++;
      count++;
    }
  }
  // Pad the result with zeros to make it the same length as the body
  while (result.length < body.storage.length) {
    result.push("0");
  }
  return {
    storage: result,
    len: count.toString()
  };
}

/**
 * @description Generate circuit inputs for the EmailVerifier circuit from raw email content
 * @param rawEmail Full email content as a buffer or string
 * @param params Arguments to control the input generation
 * @returns Circuit inputs for the EmailVerifier circuit
 */
export async function generateEmailVerifierInputs(
  rawEmail: Buffer | string,
  params: InputGenerationArgs = {}
) {
  const dkimResult = await verifyDKIMSignature(rawEmail, undefined, undefined, true);

  return generateEmailVerifierInputsFromDKIMResult(dkimResult, params);
}

/**
 * @description Generate circuit inputs for the EmailVerifier circuit from DKIMVerification result
 * @param dkimResult DKIMVerificationResult containing email data and verification result
 * @param params Arguments to control the input generation
 * @returns Circuit inputs for the EmailVerifier circuit
 */
export function generateEmailVerifierInputsFromDKIMResult(
  dkimResult: DKIMVerificationResult,
  params: InputGenerationArgs = {}
): CircuitInput {
  const { headers, body, bodyHash, publicKey, signature, modulusLength, signingDomain } = dkimResult;

  if (params.expectedDomain) {
    // Accept the DKIM signing domain matching the expected domain exactly, or via the literal
    // "email." subdomain some providers use (e.g. `d=email.example.com` for `example.com`).
    // Strict equality only (not endsWith/pattern matching) to avoid domain-alignment bypasses
    // via lookalike subdomains like "notemail.example.com". See:
    // https://github.com/masaun/zk-email-verify/blob/specific-subdomain-check/packages/helpers/doc/SPECIFIC_SUBDOMAIN_CHECK.md
    const emailSubdomain = `email.${params.expectedDomain}`;
    if (signingDomain !== params.expectedDomain && signingDomain !== emailSubdomain) {
      throw new Error(
        `DKIM signing domain "${signingDomain}" does not match expected domain "${params.expectedDomain}" (or its "email." subdomain)`
      );
    }
  }

  // SHA add padding
  const [messagePadded] = sha256Pad(
    headers,
    params.maxHeadersLength || MAX_HEADER_PADDED_BYTES
  );

  // set inputs used in all cases
  const circuitInputs: CircuitInput = {
    header: {
      storage: Uint8ArrayToCharArray(messagePadded),
      len: headers.length.toString(),
    },
    pubkey: {
      modulus: NoirBignum.bnToLimbStrArray(publicKey, modulusLength),
      redc: NoirBignum.bnToRedcLimbStrArray(publicKey, modulusLength),
    },
    // modified from original: use noir bignum to format
    signature: NoirBignum.bnToLimbStrArray(signature, modulusLength),
    dkim_header_sequence: getHeaderSequence(headers, "dkim-signature"),
  };

  // removed: header mask

  if (!params.ignoreBodyHashCheck) {
    if (!body || !bodyHash) {
      throw new Error(
        "body and bodyHash are required when ignoreBodyHashCheck is false"
      );
    }

    const bodyHashIndex = headers.toString().indexOf(bodyHash);
    const maxBodyLength = params.maxBodyLength || MAX_BODY_PADDED_BYTES;

    // 65 comes from the 64 at the end and the 1 bit in the start, then 63 comes from the formula to round it up to the nearest 64.
    // see sha256algorithm.com for a more full explanation of padding length
    const bodySHALength = Math.floor((body.length + 63 + 65) / 64) * 64;
    const [bodyPadded, bodyPaddedLen] = sha256Pad(
      body,
      Math.max(maxBodyLength, bodySHALength)
    );

    const { precomputedSha, bodyRemainingLength, ...rest } = generatePartialSHA(
      {
        body: bodyPadded,
        bodyLength: bodyPaddedLen,
        selectorString: params.shaPrecomputeSelector,
        maxRemainingBodyLength: maxBodyLength,
      }
    );

    // code smell but it passes the linter
    let { bodyRemaining } = rest;
    // idk why this gets out of sync, todo: fix
    if (
      params.shaPrecomputeSelector &&
      bodyRemaining.length !== bodyRemainingLength
    ) {
      bodyRemaining = bodyRemaining.slice(0, bodyRemainingLength);
    }

    circuitInputs.body = {
      storage: Uint8ArrayToCharArray(bodyRemaining),
      len: body.length.toString(),
    };
    circuitInputs.body_hash_index = bodyHashIndex.toString();

    if (params.shaPrecomputeSelector) {
      // can use exact body lengths
      const selector = new TextEncoder().encode(params.shaPrecomputeSelector);
      const selectorIndex = findIndexInUint8Array(body, selector);
      const shaCutoffIndex = Math.floor(selectorIndex / 64) * 64;
      const remainingBodyLength = body.length - shaCutoffIndex;
      circuitInputs.partial_body_real_length = body.length.toString();
      circuitInputs.body.len = remainingBodyLength.toString();

      // format back into u32 so noir doesn't have to do it
      circuitInputs.partial_body_hash = Array.from(u8ToU32(precomputedSha)).map(
        (x) => x.toString()
      );
    }

    // masking
    if (params.headerMask) circuitInputs.header_mask = params.headerMask.map((x) => x.toString());
    if (params.bodyMask) circuitInputs.body_mask = params.bodyMask.map((x) => x.toString());

    // remove soft line breaks
    if (params.removeSoftLineBreaks) {
      circuitInputs.decoded_body = removeSoftLineBreaks(circuitInputs.body);
    }

    // address extraction
    if (params.extractFrom) {
      const fromSequences = getAddressHeaderSequence(headers, "from");
      circuitInputs.from_header_sequence = fromSequences[0];
      circuitInputs.from_address_sequence = fromSequences[1];
    }
    if (params.extractTo) {
      const toSequences = getAddressHeaderSequence(headers, "to");
      circuitInputs.to_header_sequence = toSequences[0];
      circuitInputs.to_address_sequence = toSequences[1];
    }
  }

  return circuitInputs;
}
