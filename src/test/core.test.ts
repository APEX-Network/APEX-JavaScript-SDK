/* eslint @typescript-eslint/explicit-function-return-type: 0 */

import {CPXKey, TransactionPayload, VERSION, FixedNumber, TX_TYPE, FRACTION} from '../core'
import Long from "long"
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

describe('TransactionPayload', () => {

    test('verify payload creation', () => {
        // setup
        const privFrom = "319c325b626dd10ae86bbfd4236dca0d93c84f72f6fbacf292cdc804ec831e9a";
        const privTo = "97b7c5875b8a5207e0cdf5b4050cb8215065ddcb36622bf733d55eca40250c39";
        const pubFrom = secp256r1.publicKeyCreate(Buffer.from(privFrom, 'hex'), true);
        const pubTo = secp256r1.publicKeyCreate(Buffer.from(privTo, 'hex'), true);
        const keyFrom = new CPXKey(pubFrom);
        const keyTo = new CPXKey(pubTo);
        const timestamp = Long.fromNumber(Date.now());
        const expectedResult = "0000000101dbfb9804c00d94875b4300cf41b6bb18d059e661edefb082ed2e9487041abe8a28a5363c61d66bd50810a741a4627800000000000000000001000602ba7def3000030493e0";
        // run
        const tx = new TransactionPayload(
            VERSION.ONE,
            TX_TYPE.TRANSFER,
            keyTo,
            keyFrom,
            new FixedNumber(1.2, FRACTION.CPX),
            new Long(1),
            Array.from([0]),
            new FixedNumber(3, FRACTION.KGP),
            new FixedNumber(300, FRACTION.KP),
            timestamp);
        // verify
        console.log(tx.toHex());
        expect(tx.toHex()).toEqual(`${expectedResult}${Buffer.from(timestamp.toBytes()).toString("hex")}`);
    });

});