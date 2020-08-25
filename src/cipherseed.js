"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CipherSeed = void 0;
const scrypt = require("scryptsy");
const rng = require("randombytes");
const mn = require("./mnemonic");
const params_1 = require("./params");
const aez = require('aez');
const crc = require('crc-32');
const BITCOIN_GENESIS = new Date('2009-01-03T18:15:05.000Z').getTime();
const daysSinceGenesis = (time) => Math.floor((time.getTime() - BITCOIN_GENESIS) / params_1.ONE_DAY);
class CipherSeed {
    constructor(entropy, salt, internalVersion = 0, birthday = daysSinceGenesis(new Date())) {
        this.entropy = entropy;
        this.salt = salt;
        this.internalVersion = internalVersion;
        this.birthday = birthday;
        if (entropy && entropy.length !== 16)
            throw new Error('incorrect entropy length');
        if (salt && salt.length !== 5)
            throw new Error('incorrect salt length');
    }
    static decipher(cipherBuf, password) {
        if (cipherBuf[0] >= params_1.PARAMS.length) {
            throw new Error('Invalid cipherSeedVersion');
        }
        const cipherSeedVersion = cipherBuf[0];
        const params = params_1.PARAMS[cipherSeedVersion];
        const checksum = Buffer.allocUnsafe(4);
        const checksumNum = crc.buf(cipherBuf.slice(0, 29));
        checksum.writeInt32BE(checksumNum);
        if (!checksum.equals(cipherBuf.slice(29))) {
            throw new Error('CRC checksum mismatch');
        }
        const salt = cipherBuf.slice(24, 29);
        const key = scrypt(Buffer.from(password, 'utf8'), salt, params.n, params.r, params.p, 32);
        const adBytes = Buffer.allocUnsafe(6);
        adBytes.writeUInt8(cipherSeedVersion, 0);
        salt.copy(adBytes, 1);
        const plainText = aez.decrypt(key, null, [adBytes], 4, cipherBuf.slice(1, 24));
        if (plainText === null)
            throw new Error('Invalid Password');
        return new CipherSeed(plainText.slice(3, 19), salt, plainText[0], plainText.readUInt16BE(1));
    }
    static fromMnemonic(mnemonic, password = params_1.DEFAULT_PASSWORD) {
        const bytes = mn.mnemonicToBytes(mnemonic);
        return CipherSeed.decipher(bytes, password);
    }
    static random() {
        return new CipherSeed(rng(16), rng(5));
    }
    static changePassword(mnemonic, oldPassword, newPassword) {
        const pwd = oldPassword === null ? params_1.DEFAULT_PASSWORD : oldPassword;
        const cs = CipherSeed.fromMnemonic(mnemonic, pwd);
        return cs.toMnemonic(newPassword);
    }
    get birthDate() {
        return new Date(BITCOIN_GENESIS + this.birthday * params_1.ONE_DAY);
    }
    toMnemonic(password = params_1.DEFAULT_PASSWORD, cipherSeedVersion = params_1.CIPHER_SEED_VERSION) {
        return mn.mnemonicFromBytes(this.encipher(password, cipherSeedVersion));
    }
    encipher(password, cipherSeedVersion) {
        const pwBuf = Buffer.from(password, 'utf8');
        const params = params_1.PARAMS[cipherSeedVersion];
        const key = scrypt(pwBuf, this.salt, params.n, params.r, params.p, 32);
        const seedBytes = Buffer.allocUnsafe(19);
        seedBytes.writeUInt8(this.internalVersion, 0);
        seedBytes.writeUInt16BE(this.birthday, 1);
        this.entropy.copy(seedBytes, 3);
        const adBytes = Buffer.allocUnsafe(6);
        adBytes.writeUInt8(cipherSeedVersion, 0);
        this.salt.copy(adBytes, 1);
        const cipherText = aez.encrypt(key, null, [adBytes], 4, seedBytes);
        const cipherSeedBytes = Buffer.allocUnsafe(33);
        cipherSeedBytes.writeUInt8(cipherSeedVersion, 0);
        cipherText.copy(cipherSeedBytes, 1);
        this.salt.copy(cipherSeedBytes, 24);
        const checksumNum = crc.buf(cipherSeedBytes.slice(0, 29));
        cipherSeedBytes.writeInt32BE(checksumNum, 29);
        return cipherSeedBytes;
    }
}
exports.CipherSeed = CipherSeed;
