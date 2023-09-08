// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { Client2, Issuer2, PrivateToken, TOKEN_TYPES, keyGen2 } from '../src/index.js';

export async function privateVerifiableTokens(): Promise<void> {
    // Protocol Setup
    //
    // [ Everybody ] decided to use Private Verifiable Tokens.

    // [ Issuer ] creates a key pair.
    const keys = await keyGen2();
    const issuer = new Issuer2('issuer.com', keys.privateKey, keys.publicKey);

    // [ Client ] creates a state.
    const client = new Client2();

    // Online Protocol
    //
    // +--------+            +--------+         +----------+ +--------+
    // | Origin |            | Client |         | Attester | | Issuer |
    // +---+----+            +---+----+         +----+-----+ +---+----+
    //     |                     |                   |           |
    //     |<----- Request ------+                   |           |
    const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
    const originInfo = ['origin.example.com', 'origin2.example.com'];
    const tokChl = await PrivateToken.create(
        TOKEN_TYPES.VOPRF,
        issuer,
        redemptionContext,
        originInfo,
    );
    //     +-- TokenChallenge -->|                   |           |
    //     |                     |<== Attestation ==>|           |
    //     |                     |                   |           |
    const tokReq = await client.createTokenRequest(tokChl);
    //     |                     +--------- TokenRequest ------->|
    //     |                     |                   |           |
    const tokRes = await issuer.issue(tokReq);
    //     |                     |<-------- TokenResponse -------+
    //     |                     |                   |           |
    const token = await client.finalize(tokRes);
    //     |<-- Request+Token ---+                   |           |
    //     |                     |                   |           |
    const isValid = await /*Issuer*/ token.verify(keys.privateKey);
    console.log(`Valid Private-Verifiable token? ${isValid}`);
}
