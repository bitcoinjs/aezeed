import * as scrypt from 'scryptsy';
import * as rng from 'randombytes';
import * as mn from './mnemonic';
import {
  PARAMS,
  DEFAULT_PASSWORD,
  ONE_DAY,
  CIPHER_SEED_VERSION,
} from './params';
const aez = require('aez');
const crc = require('crc-32');

const BITCOIN_GENESIS = new Date('2009-01-03T18:15:05.000Z').getTime();
export const daysSinceGenesis = (time: Date): number =>
  Math.floor((time.getTime() - BITCOIN_GENESIS) / ONE_DAY);

export class CipherSeed {
  private static decipher(cipherBuf: Buffer, password: string): CipherSeed {
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

    return new CipherSeed(
      plainText.slice(3, 19),
      salt,
      plainText[0],
      plainText.readUInt16BE(1),
    );
  }

  static fromMnemonic(
    mnemonic: string,
    password: string = DEFAULT_PASSWORD,
  ): CipherSeed {
    const bytes = mn.mnemonicToBytes(mnemonic);
    return CipherSeed.decipher(bytes, password);
  }

  static random(): CipherSeed {
    return new CipherSeed(rng(16), rng(5));
  }

  static changePassword(
    mnemonic: string,
    oldPassword: string | null,
    newPassword: string,
  ): string {
    const pwd = oldPassword === null ? DEFAULT_PASSWORD : oldPassword;
    const cs = CipherSeed.fromMnemonic(mnemonic, pwd);
    return cs.toMnemonic(newPassword);
  }

  constructor(
    public entropy: Buffer,
    public salt: Buffer,
    public internalVersion: number = 0,
    public birthday: number = daysSinceGenesis(new Date()),
  ) {
    if (entropy && entropy.length !== 16)
      throw new Error('incorrect entropy length');
    if (salt && salt.length !== 5) throw new Error('incorrect salt length');
  }

  get birthDate(): Date {
    return new Date(BITCOIN_GENESIS + this.birthday * ONE_DAY);
  }

  toMnemonic(
    password: string = DEFAULT_PASSWORD,
    cipherSeedVersion: number = CIPHER_SEED_VERSION,
  ): string {
    return mn.mnemonicFromBytes(this.encipher(password, cipherSeedVersion));
  }

  private encipher(password: string, cipherSeedVersion: number): Buffer {
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
}
