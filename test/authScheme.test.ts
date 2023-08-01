// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { TokenType as PubTokenType } from '../src/pubVerifToken.js';
import { TokenChallenge, TokenPayload, parsePrivateTokens } from '../src/httpAuthScheme.js';

// Test vectors generated by pat-go (https://github.com/cloudflare/pat-go/)
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-11#name-test-vectors
import tokenVectors from './testdata/authscheme_token_v11.json';
import headerVectors from './testdata/authscheme_header_v11.json';

function hexToString(x: string): string {
    return Buffer.from(x, 'hex').toString();
}

function hexToUint8(x: string): Uint8Array {
    return new Uint8Array(Buffer.from(x, 'hex'));
}

function uint8ToHex(x: Uint8Array): string {
    return Buffer.from(x).toString('hex');
}

type TokenVectors = (typeof tokenVectors)[number];

test.each(tokenVectors)('AuthScheme-TokenVector-%#', async (v: TokenVectors) => {
    const tokenType = parseInt(v.token_type);
    if (tokenType !== PubTokenType.value) {
        return;
    }

    const issuerName = hexToString(v.issuer_name);
    const redemptionContext = hexToUint8(v.redemption_context);
    const originInfoAll = hexToString(v.origin_info);
    const originInfo = originInfoAll.split(',');
    const nonce = hexToUint8(v.nonce);
    const keyId = hexToUint8(v.token_key_id);

    const challenge = new TokenChallenge(tokenType, issuerName, redemptionContext, originInfo);
    const challengeSerialized = challenge.serialize();
    const context = new Uint8Array(await crypto.subtle.digest('SHA-256', challengeSerialized));
    const payload = new TokenPayload(tokenType, nonce, context, keyId);
    const authenticator = payload.serialize();
    expect(uint8ToHex(authenticator)).toBe(v.token_authenticator_input);
});

type HeaderVectors = (typeof headerVectors)[number];

test.each(headerVectors)('AuthScheme-HeaderVector-%#', async (v: HeaderVectors) => {
    const tokens = parsePrivateTokens(v['WWW-Authenticate']);
    let i = 0;
    for (const t of tokens) {
        expect(uint8ToHex(t.challengeSerialized)).toBe(v[`token-challenge-${i}` as keyof typeof v]);
        expect(uint8ToHex(t.tokenKey)).toBe(v[`token-key-${i}` as keyof typeof v]);
        expect(t.challenge.tokenType).toBe(v[`token-type-${i}` as keyof typeof v]);
        expect(t.maxAge).toBe(v[`max-age-${i}` as keyof typeof v]);
        i += 1;
    }
});
