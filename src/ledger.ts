/*
* This file is a rewrite of
*
* https://github.com/CityOfZion/neon-wallet/blob/dev/app/ledger/neonLedger.js
*
*/

import {cloneDeep} from 'lodash-es'
import { u } from '@cityofzion/neon-js'
import LedgerNode from '@ledgerhq/hw-transport-node-hid'

/*
* Ledger response codes
* @type {number}
*/
const VALID_STATUS = 0x9000;
const MSG_TOO_BIG = 0x6d08;
const APP_CLOSED = 0x6e00;
const TX_DENIED = 0x6985;
const TX_PARSE_ERR = 0x6d07;

export const BIP44_PATH = '8000002C' + '80000378' + '80000000' + '00000000';

export const MESSAGES = {
    NOT_SUPPORTED: 'Ledger is not supported',
    NOT_CONNECTED: 'Ledger is not connected',
    APP_CLOSED: 'Ledger application is not open',
    MSG_TOO_BIG: 'The transaction is too long',
    TX_DENIED: 'The transaction was denied',
    TX_PARSE_ERR: 'Transaction could not be parsed',
    UNEXPECTED: 'Undefined error occurred'
};

const BIP44 = (acct = 0) => {
    const acctNumber = acct.toString(16);
    return `${BIP44_PATH}${'0'.repeat(8 - acctNumber.length)}${acctNumber}`;
};

/*
* This function maps error codes to error messages
* @param error
* @returns {*}
*/
const evalTransportError = error => {
    const err = cloneDeep(error);
    switch (err.statusCode) {
        case APP_CLOSED:
            err.message = MESSAGES.APP_CLOSED;
            break;
        case MSG_TOO_BIG:
            err.message = MESSAGES.MSG_TOO_BIG;
            break;
        case TX_DENIED:
            err.message = MESSAGES.TX_DENIED;
            break;
        case TX_PARSE_ERR:
            err.message = MESSAGES.TX_PARSE_ERR;
            break;
        default:
            err.message = MESSAGES.UNEXPECTED;
    }
    return err;
};

function asyncWrap(promise) {
    return promise.then(data => [null, data]).catch(err => [err]);
}

/*
* This class bundles Ledger interaction functionality
*/
export default class CPXLedger {

    path: string;
    device: any;

    constructor(path: string) {
        this.path = path;
    }

    /*
    * Initialises by listing devices and trying to find a ledger device connected.
    * Throws an error if no ledgers detected or unable to connect.
    * @return {Promise<CPXLedger>}
    */
    static async init() {
        const supported = await LedgerNode.isSupported();
        if (!supported) throw new Error(MESSAGES.NOT_SUPPORTED);
        const paths = await CPXLedger.list();
        if (paths.length === 0) throw new Error(MESSAGES.NOT_CONNECTED);
        return new CPXLedger(paths[0]).open();
    }

    static async list(): Promise<string[]> {
        return LedgerNode.list()
    }

    /*
    * Opens an connection with the selected ledger.
    * @return {Promise<CPXLedger>} this
    */
    async open(): Promise<CPXLedger> {
        try {
            this.device = await LedgerNode.open(this.path);
            return this;
        } catch (err) {
            throw evalTransportError(err);
        }
    }

    /*
    * Sends an message with params over to the Ledger.
    * @param {string} params - params as a hexstring
    * @param {string} msg - Message as a hexstring
    * @param {number[]} statusList - Statuses to return
    * @return {Promise<Buffer>} return value decoded to ASCII string
    */
    async send(params: string, msg: string, statusList: number[]): Promise<Buffer> {
        if (params.length !== 8) throw new Error('params requires 4 bytes');
        const [cla, ins, p1, p2] = params.match(/.{1,2}/g).map(i => parseInt(i, 16));
        try {
            return await this.device.send(cla, ins, p1, p2, Buffer.from(msg).toString('hex'), statusList);
        } catch (err) {
            throw evalTransportError(err);
        }
    }

    /*
    * Closes the connection between the Ledger and the wallet.
    * @return {Promise<void>}}
    */
    close(): Promise<void> {
        if (this.device) return this.device.close();
        return Promise.resolve();
    }

    async getPublicKeys(acct: number = 0,
        unencodedPublicKeys: Array<{ account: number, key: string }> = [],
        batchSize: number = 10) {
        const res = await this.send('80040000', BIP44(acct), [VALID_STATUS]);
        const key = await res.toString('hex').substring(0, 130);
        if (unencodedPublicKeys.length < batchSize) {
            unencodedPublicKeys.push({ account: acct, key });
            return this.getPublicKeys( acct + 1, unencodedPublicKeys);
        }
        return unencodedPublicKeys;
    }

    /*
    * Retrieves the public key of an account from the Ledger.
    * @param {number} [acct] - Account that you want to retrieve the public key from.
    * @return {string} Public Key (Unencoded)
    */
    async getPublicKey(acct: number = 0): Promise<{ account: number, key: string }> {
        const res = await this.send('80040000', BIP44(acct), [VALID_STATUS]);
        const key = await res.toString('hex').substring(0, 130);
        return { account: acct, key };
    }

    getDeviceInfo() {
        try {
            return this.device.device.getDeviceInfo();
        } catch (err) {
            throw evalTransportError(err);
        }
    }

    /*
    * Gets the ECDH signature of the data from Ledger using acct
    * @param {string} data
    * @param {number} [acct]
    * @return {Promise<string>}
    */
    async getSignature(data: string, acct: number = 0): Promise<string> {
        data += BIP44(acct);
        let response = null;
        const chunks = data.match(/.{1,510}/g) || [];
        if (!chunks.length) throw new Error("Invalid data provided:" + data);
        for (let i = 0; i < chunks.length; i++) {
            const p = i === chunks.length - 1 ? '80' : '00';
            const chunk = chunks[i];
            const params = `8002${p}00`;
            const [err, res] = await asyncWrap(this.send(params, chunk, [VALID_STATUS]));
            if (err) throw evalTransportError(err);
            response = res;
        }
        if (response === 0x9000) throw new Error('No more data but Ledger did not return signature!');
        return assembleSignature(Buffer.from(response).toString('hex'));
    }
}

/*
* The signature is returned from the ledger in a DER format
* @param {string} response - Signature in DER format
*/
const assembleSignature = (response: string): string => {
    const ss = new u.StringStream(response);
    // The first byte is format. It is usually 0x30 (SEQ) or 0x31 (SET)
    // The second byte represents the total length of the DER module.
    ss.read(2);
    // Now we read each field off
    // Each field is encoded with a type byte, length byte followed by the data itself
    ss.read(1); // Read and drop the type
    const r = ss.readVarBytes();
    ss.read(1);
    const s = ss.readVarBytes();
    // We will need to ensure both integers are 32 bytes long
    const integers = [r, s].map(i => {
        if (i.length < 64) i = i.padStart(64, '0');
        if (i.length > 64) i = i.substr(-64);
        return i;
    });
    return integers.join('');
};

export const getPublicKeys = async (acct: number = 0): Promise<Array<{ account: number, key: string }>> => {
    const ledger = await CPXLedger.init();
    try {
        return await ledger.getPublicKeys(acct)
    } finally {
        await ledger.close()
    }
};

export const getDeviceInfo = async () => {
    const ledger = await CPXLedger.init();
    try {
        const deviceInfo = await ledger.getDeviceInfo();
        const publicKey = await ledger.getPublicKey();
        return { deviceInfo, publicKey }
    } finally {
        await ledger.close()
    }
};

/*
* Signs a transaction with Ledger. Returns the whole transaction string
* @param data - Hex string to sign
* @param {number} acct - The account to sign with.
* @return {string} Transaction as a Hex string.
*/
export const signWithLedger = async (data: string, acct: number = 0): Promise<string> => {
    const ledger = await CPXLedger.init();
    try {
        const signature = Buffer.from(await ledger.getSignature(data, acct)).toString('hex');
        const signature_length = Buffer.from(signature).length.toString(16);
        return data + signature_length + signature;
    } finally {
        await ledger.close();
    }
};