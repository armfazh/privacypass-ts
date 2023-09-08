// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import voprf from '@cloudflare/voprf-ts';

import { TokenTypeEntry, PrivateToken, TokenPayload, Token } from './httpAuthScheme.js';
import { joinAll } from './util.js';
import {
    getIssuerUrl,
    TokenResponseProtocol,
    TokenRequestProtocol,
    MediaType,
} from './issuance.js';

export function keyGen2(): Promise<{ privateKey: Uint8Array, publicKey: Uint8Array }> {
    return voprf.generateKeyPair(voprf.Oprf.Suite.P384_SHA384)
}

// Token Type Entry Update:
//  - Token Type VOPRF (P-384, SHA-384)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-12#name-token-type-registry-updates
export const VOPRF = {
    value: 0x0001,
    name: 'VOPRF (P-384, SHA-384)',
    Nk: 48,
    Nid: 32,
    Ne: 49,
    Ns: 48,
    publicVerifiable: false,
    publicMetadata: false,
    privateMetadata: false,
} as const;

export class TokenRequest2 implements TokenRequestProtocol {
    // struct {
    //     uint16_t token_type = 0x0001; /* Type VOPRF(P-384, SHA-384) */
    //     uint8_t truncated_token_key_id;
    //     uint8_t blinded_msg[Ne];
    //   } TokenRequest;

    tokenType: number;
    constructor(
        public tokenKeyId: number,
        public blindedMsg: Uint8Array,
    ) {
        if (blindedMsg.length !== VOPRF.Ne) {
            throw new Error('invalid blinded message size');
        }

        this.tokenType = VOPRF.value;
    }

    static deserialize(bytes: Uint8Array): TokenRequest2 {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const type = input.getUint16(offset);
        offset += 2;

        if (type !== VOPRF.value) {
            throw new Error('mismatch of token type');
        }

        const tokenKeyId = input.getUint8(offset);
        offset += 1;

        const len = VOPRF.Ne;
        const blindedMsg = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        return new TokenRequest2(tokenKeyId, blindedMsg);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.tokenKeyId);
        output.push(b);

        b = this.blindedMsg.buffer;
        output.push(b);

        return new Uint8Array(joinAll(output));
    }

    // Send TokenRequest to Issuer (fetch w/POST).
    async send<T extends TokenResponseProtocol>(
        issuerUrl: string,
        tokRes: { deserialize(_: Uint8Array): T },
        headers?: Headers,
    ): Promise<T> {
        headers ??= new Headers();
        headers.append('Content-Type', MediaType.PRIVATE_TOKEN_REQUEST);
        headers.append('Accept', MediaType.PRIVATE_TOKEN_RESPONSE);
        const issuerResponse = await fetch(issuerUrl, {
            method: 'POST',
            headers,
            body: this.serialize().buffer,
        });

        if (issuerResponse.status !== 200) {
            const body = await issuerResponse.text();
            throw new Error(
                `tokenRequest failed with code:${issuerResponse.status} response:${body}`,
            );
        }

        const contentType = issuerResponse.headers.get('Content-Type');

        if (!contentType || contentType.toLowerCase() !== MediaType.PRIVATE_TOKEN_RESPONSE) {
            throw new Error(`tokenRequest: missing ${MediaType.PRIVATE_TOKEN_RESPONSE} header`);
        }

        //  Receive a TokenResponse,
        const resp = new Uint8Array(await issuerResponse.arrayBuffer());
        return tokRes.deserialize(resp);
    }
}

export class TokenResponse2 implements TokenResponseProtocol {
    // struct {
    //     uint8_t evaluate_msg[Ne];
    //     uint8_t evaluate_proof[Ns+Ns];
    //  } TokenResponse;
    evaluate_msg: Uint8Array
    evaluate_proof: Uint8Array

    constructor(public evaluation: voprf.Evaluation) {
        if (evaluation.evaluated.length === 0) {
            throw new Error('evaluation has no elements')
        }
        const evaluate_msg = evaluation.evaluated[0].serialize()
        if (evaluate_msg.length !== VOPRF.Ne) {
            throw new Error('evaluate_msg has invalid size')
        }
        this.evaluate_msg = evaluate_msg

        if (typeof evaluation.proof === 'undefined') {
            throw new Error('evaluation has no proof')
        }
        const evaluate_proof = evaluation.proof.serialize()
        if (evaluate_proof.length !== 2 * VOPRF.Ns) {
            throw new Error('evaluate_proof has invalid size')
        }
        this.evaluate_proof = evaluate_proof
    }

    static deserialize(bytes: Uint8Array): TokenResponse2 {
        const suite = voprf.Oprf.Suite.P384_SHA384
        const gg = voprf.Oprf.getGroup(suite)
        const params = {
            gg,
            hash: voprf.Oprf.getHash(suite),
            dst: ''
        }

        let start = 0;
        let end = VOPRF.Ne;
        const msgBytes = bytes.slice(start, end);
        const msg = voprf.Elt.deserialize(gg, msgBytes);

        start = end;
        end += 2 * VOPRF.Ns
        const proofBytes = bytes.slice(start, end);
        const proof = voprf.DLEQProof.deserialize(params, proofBytes);

        const evaluation = new voprf.Evaluation(voprf.Oprf.Mode.VOPRF, [msg], proof)
        return new TokenResponse2(evaluation);
    }

    serialize(): Uint8Array {
        return new Uint8Array(joinAll([this.evaluate_msg, this.evaluate_proof]))
    }
}

export class PrivateVerifiableToken extends Token {
    static async fetch(pt: PrivateToken): Promise<PrivateVerifiableToken> {
        const issuerUrl = await getIssuerUrl(pt.challenge.issuerName);
        const client = new Client2();
        const tokReq = await client.createTokenRequest(pt);
        const tokRes = await tokReq.send(issuerUrl, TokenResponse2);
        const token = await client.finalize(tokRes);
        return token;
    }

    static deserialize(tokenTypeEntry: TokenTypeEntry, bytes: Uint8Array): PrivateVerifiableToken {
        return Token.deserializeWithType(PrivateVerifiableToken, tokenTypeEntry, bytes);
    }

    verify(privateKeyIssuer: Uint8Array): Promise<boolean> {
        const vServer = new voprf.VOPRFServer(voprf.Oprf.Suite.P384_SHA384, privateKeyIssuer)
        const tokenInput = this.payload.serialize()
        return vServer.verifyFinalize(tokenInput, this.authenticator)
    }
}

export class Issuer2 {
    static readonly TYPE = VOPRF;

    private vServer: voprf.VOPRFServer

    constructor(
        public name: string,
        private privateKey: Uint8Array,
        public publicKey: Uint8Array,
    ) {
        this.vServer = new voprf.VOPRFServer(voprf.Oprf.Suite.P384_SHA384, this.privateKey)
    }

    async issue(tokReq: TokenRequest2): Promise<TokenResponse2> {
        const evalReq = voprf.EvaluationRequest.deserialize(this.vServer.gg, tokReq.blindedMsg);
        const evaluation = await this.vServer.blindEvaluate(evalReq)
        return new TokenResponse2(evaluation);
    }

    verify(token: PrivateVerifiableToken): Promise<boolean> {
        const tokenInput = token.payload.serialize()
        return this.vServer.verifyFinalize(tokenInput, token.authenticator)
    }
}

export class Client2 {
    static readonly TYPE = VOPRF;
    private finData?: {
        tokenInput: Uint8Array;
        tokenPayload: TokenPayload;
        tokenRequest: TokenRequest2;
        vClient: voprf.VOPRFClient;
        finData: voprf.FinalizeData;
    };

    async createTokenRequest(privToken: PrivateToken): Promise<TokenRequest2> {
        // https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-11#section-6.1
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const context = new Uint8Array(
            await crypto.subtle.digest('SHA-256', privToken.challengeSerialized),
        );
        const keyId = new Uint8Array(await crypto.subtle.digest('SHA-256', privToken.tokenKey));
        const tokenPayload = new TokenPayload(Client2.TYPE, nonce, context, keyId);
        const tokenInput = tokenPayload.serialize();

        const vClient = new voprf.VOPRFClient(voprf.Oprf.Suite.P384_SHA384, privToken.tokenKey)
        const [finData, evalReq] = await vClient.blind([tokenInput])
        const tokenKeyId = keyId[keyId.length - 1];
        const tokenRequest = new TokenRequest2(tokenKeyId, evalReq.serialize());
        this.finData = { vClient, tokenInput, tokenPayload, finData, tokenRequest };

        return tokenRequest;
    }

    async finalize(t: TokenResponse2): Promise<PrivateVerifiableToken> {
        if (!this.finData) {
            throw new Error('no token request was created yet.');
        }

        const { vClient, finData, tokenPayload } = this.finData;
        const [authenticator] = await vClient.finalize(finData, t.evaluation)
        const token = new PrivateVerifiableToken(Client2.TYPE, tokenPayload, authenticator,
        );
        this.finData = undefined;

        return token;
    }
}
