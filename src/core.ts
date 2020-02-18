import Long from 'long'
import BigInteger from 'bigi'
import Base58check from 'base58check'
import Crypto from 'bitcoinjs-lib/src/crypto'

export const FRACTION = {
    P : 1,
    KP: 1000,
    MP: 1000000,
    GP: 1000000000,
    KGP: 1000000000000,
    MGP: 1000000000000000,
    CPX: 1000000000000000000
};

export const VERSION = {
    ONE: "00000001"
};

export const TX_TYPE = {
    MINER: "00",
    TRANSFER: "01",
    DEPLOY: "02",
    CALL: "03",
    REFUND: "04",
    SCHEDULE: "05"
};

function getHexFromBytes(bytes: number[]) {
    const length_hex = bytes.length < 16 ? "0" + bytes.length.toString(16) : bytes.length.toString(16);
    const bytes_hex = Buffer.from(bytes).toString("hex");
    return `${length_hex}${bytes_hex}`;
}

export class FixedNumber {

    value: number;

    constructor(amount: number, fraction: number) {
        this.value = amount * fraction;
    }

    toHex(){
        return getHexFromBytes(BigInteger(this.value.toString()).toByteArray());
    }

}

export class CPXKey {

    CPX_PREFIX = '0548';
    SCRIPT_PREFIX = '21';
    SCRIPT_POSTFIX = 'ac';

    pubkey: Buffer;

    constructor(pubkey: Buffer) {
        this.pubkey = pubkey;
    }

    getScriptHash(){
        const val = Buffer.from(this.SCRIPT_PREFIX + this.pubkey.toString('hex') + this.SCRIPT_POSTFIX, 'hex');
        return Buffer.from(Crypto.hash160(val)).toString('hex');
    }

    getAddress(){
        return Base58check.encode(this.getScriptHash(), this.CPX_PREFIX);
    }

}

export class TransactionPayload {

    version: string;
    txType: string;
    fromPubKeyHash: CPXKey;
    toPubKeyHash: CPXKey;
    amount: FixedNumber;
    nonce: Long;
    data: number[];
    gasPrice: FixedNumber;
    gasLimit: FixedNumber;

    constructor(version: string, txType: string, fromPubKeyHash: CPXKey, toPubKeyHash: CPXKey,
                amount: FixedNumber, nonce: Long, data: number[], gasPrice: FixedNumber, gasLimit: FixedNumber) {
        this.version = version;
        this.txType = txType;
        this.fromPubKeyHash = fromPubKeyHash;
        this.toPubKeyHash = toPubKeyHash;
        this.amount = amount;
        this.nonce = nonce;
        this.data = data;
        this.gasPrice = gasPrice;
        this.gasLimit = gasLimit;
    }

    toHex(){
        return `${this.version}${this.txType}${this.toPubKeyHash.getScriptHash()}`+
        `${this.fromPubKeyHash.getScriptHash()}${this.amount.toHex()}`+
        `${Buffer.from(this.nonce.toBytes()).toString("hex")}`+
        `${this.data.length > 1 ? getHexFromBytes(this.data) : "00"}${this.gasPrice.toHex()}${this.gasLimit.toHex()}`;
    }

}