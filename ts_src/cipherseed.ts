import * as scrypt from 'scryptsy';
import * as rng from 'randombytes';
import * as mn from './mnemonic';
const aez = require('aez');
const crc = require('crc-32');

const PARAMS = [
  {
    // version 0
    n: 32768,
    r: 8,
    p: 1,
  },
];

const DEFAULT_PASSWORD = 'aezeed';
const BITCOIN_GENESIS = new Date('2009-01-03T18:15:05.000Z').getTime();
const CIPHER_SEED_VERSION = 0;

export class CipherSeed {
  entropy: Buffer;
  birthday: number;
  private salt: Buffer;

  private static decipher(
    cipherBuf: Buffer,
    password: string = DEFAULT_PASSWORD,
  ): CipherSeed {
    if (cipherBuf[0] >= PARAMS.length) {
      throw new Error('Invalid cipherSeedVersion');
    }
    const cipherSeedVersion = cipherBuf[0];
    const params = PARAMS[cipherSeedVersion];

    const checksum = Buffer.allocUnsafe(4);
    const checksumNum = crc.buf(cipherBuf.slice(0, 29));
    checksum.writeInt32BE(checksumNum);
    if (!checksum.equals(cipherBuf.slice(29))) {
      throw new Error('CRC checksum mismatch');
    }
    const salt = cipherBuf.slice(24, 29);
    const key = scrypt(
      Buffer.from(password, 'utf8'),
      salt,
      params.n,
      params.r,
      params.p,
      32,
    );

    const adBytes = Buffer.allocUnsafe(6);
    adBytes.writeUInt8(cipherSeedVersion, 0);
    salt.copy(adBytes, 1);

    const plainText: Buffer | null = aez.decrypt(
      key,
      null,
      [adBytes],
      4,
      cipherBuf.slice(1, 24),
    );
    if (plainText === null) throw new Error('Invalid Password');

    const newCS = new CipherSeed();
    newCS.internalVersion = plainText[0];
    newCS.birthday = plainText.readUInt16BE(1);
    newCS.entropy = plainText.slice(3, 19);
    newCS.salt = salt;
    return newCS;
  }

  static fromMnemonic(
    mnemonic: string,
    password: string = DEFAULT_PASSWORD,
  ): CipherSeed {
    const bytes = mn.mnemonicToBytes(mnemonic);
    return CipherSeed.decipher(bytes, password);
  }

  constructor(
    public internalVersion: number = 0,
    entropy?: Buffer,
    now?: Date,
  ) {
    if (entropy && entropy.length !== 16)
      throw new Error('incorrect entropy length');
    this.entropy = entropy ? entropy : rng(16);
    const birthDate = now ? now : new Date();
    this.birthday = Math.floor(
      (birthDate.getTime() - BITCOIN_GENESIS) / (24 * 60 * 60 * 1000),
    );
    this.salt = rng(5);
  }

  private encipher(
    password: string = DEFAULT_PASSWORD,
    cipherSeedVersion: number = CIPHER_SEED_VERSION,
  ): Buffer {
    const pwBuf = Buffer.from(password, 'utf8');
    const params = PARAMS[cipherSeedVersion];
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

  toMnemonic(
    password: string = DEFAULT_PASSWORD,
    cipherSeedVersion: number = CIPHER_SEED_VERSION,
  ): string {
    return mn.mnemonicFromBytes(this.encipher(password, cipherSeedVersion));
  }
}
