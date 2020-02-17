/* eslint @typescript-eslint/explicit-function-return-type: 0 */

import { CPXKey } from '../core';
const secp256r1 = require('secp256r1/elliptic');

describe('CPXKey', () => {
    test('verify address creation', () => {
        // setup
        const priv = '319c325b626dd10ae86bbfd4236dca0d93c84f72f6fbacf292cdc804ec831e9a';
        const pub = secp256r1.publicKeyCreate(Buffer.from(priv, 'hex'));
        const compressed = secp256r1.publicKeyConvert(pub, true);
        const expectedAddress = 'APN1fbsFGv4sgjktz25i5EaNKDKHeJmqkMh';

        // run
        const key = new CPXKey(pub);

        // verify
        expect(key.getAddress()).toEqual(expectedAddress);
    });
});