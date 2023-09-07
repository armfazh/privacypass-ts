// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { base64url } from 'rfc4648';
import { convertEncToRSASSAPSS, convertRSASSAPSSToEnc } from './util.js';
import { PrivateToken, TokenTypeEntry } from './httpAuthScheme.js';
import { BLIND_RSA, PublicVerifiableToken } from './pubVerifToken.js';

export const util = { convertEncToRSASSAPSS, convertRSASSAPSSToEnc };
export * from './pubVerifToken.js';
export * from './httpAuthScheme.js';
export * from './issuance.js';

// Privacy Pass Token Type Registry
// Updates:
//  - Token Type Blind RSA (2048-bit)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-12#name-token-type-registry-updates
export const TOKEN_TYPES: Record<string, TokenTypeEntry> = {
    // Token Type Blind RSA (2048-bit)
    BLIND_RSA,
} as const;

export async function header_to_token(header: string): Promise<string | null> {
    const privateTokens = PrivateToken.parseMultiple(header);
    if (privateTokens.length === 0) {
        return null;
    }

    // Takes the first one.
    const pt = privateTokens[0];
    const tokenType = pt.challenge.tokenType;
    switch (tokenType) {
        case TOKEN_TYPES.BLIND_RSA.value: {
            const token = await PublicVerifiableToken.fetch(pt);
            const encodedToken = base64url.stringify(token.serialize());
            return encodedToken;
        }

        default:
            console.log(`unrecognized or non-supported type of challenge: ${tokenType}`);
    }
    return null;
}
