import { mocked } from 'ts-jest/utils';
import * as params from './params';
jest.mock('./params');
const mockedParams = mocked(params, true);
mockedParams.PARAMS[0] = {
  n: 16,
  r: 8,
  p: 1,
};
import { CipherSeed } from './cipherseed';

const entropy = Buffer.from('dadeb38984dadeb38984dadeb3898442', 'hex');
const CSEED = new CipherSeed(entropy, Buffer.from('dadeb38984', 'hex'), 0, 0);
const mnemonic =
  'abandon razor cage merit again upon sort only grace brother ' +
  'dinosaur reform path poverty despair detail tattoo bitter ' +
  'response grow obscure broccoli dirt swallow';

const wrongChecksum =
  'above judge emerge veteran reform crunch system all ' +
  'snap please shoulder vault hurt city quarter cover enlist ' +
  'swear success suggest drink wagon enrich boil';
const wrongVersion =
  'airport judge emerge veteran reform crunch system all ' +
  'snap please shoulder vault hurt city quarter cover enlist ' +
  'swear success suggest drink wagon enrich body';

describe('CipherSeed', () => {
  it('should decode from mnemonic', () => {
    const cSeed = CipherSeed.fromMnemonic(mnemonic);
    expect(cSeed).toEqual(CSEED);
  });
  it('should encode to the same mnemonic', () => {
    const newMnemonic = CSEED.toMnemonic();
    expect(newMnemonic).toEqual(mnemonic);
  });
  it('should get birthDate', () => {
    expect(CSEED.birthDate).toEqual(new Date('2009-01-03T18:15:05.000Z'));
  });
  it('should allow changing password', () => {
    const newMnemonic = CipherSeed.changePassword(mnemonic, null, 'notDefault');
    const sameMnemonic = CipherSeed.changePassword(
      newMnemonic,
      'notDefault',
      'aezeed',
    );
    expect(newMnemonic).toEqual(
      'abandon ski rough double differ easy match patient dynamic ' +
        'engage crystal artefact attract puppy slam abstract outer ' +
        'item response grow obscure amount vivid vessel',
    );
    expect(sameMnemonic).toEqual(mnemonic);
  });
  it('should encode and decode with password', () => {
    const seed = CipherSeed.random();
    const mnemonic = seed.toMnemonic('strongPw');
    const seed2 = CipherSeed.fromMnemonic(mnemonic, 'strongPw');
    expect(seed2).toEqual(seed);
  });
  it('should generate a random mnemonic', () => {
    expect(CipherSeed.random()).toBeTruthy();
  });
  it('should fail on incorrect checksum', () => {
    expect(() => {
      CipherSeed.fromMnemonic(wrongChecksum);
    }).toThrow(/^CRC checksum mismatch$/);
  });
  it('should fail on incorrect version', () => {
    expect(() => {
      CipherSeed.fromMnemonic(wrongVersion);
    }).toThrow(/^Invalid cipherSeedVersion$/);
  });
  it('should fail on incorrect password', () => {
    expect(() => {
      CipherSeed.fromMnemonic(mnemonic, 'wrong');
    }).toThrow(/^Invalid Password$/);
  });
  it('should fail on incorrect entropy length', () => {
    expect(() => {
      new CipherSeed(Buffer.from([1, 2, 3]), Buffer.from([1, 2, 3, 4, 5]));
    }).toThrow(/^incorrect entropy length$/);
  });
  it('should fail on incorrect salt length', () => {
    expect(() => {
      new CipherSeed(
        Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        Buffer.from([1, 2, 3]),
      );
    }).toThrow(/^incorrect salt length$/);
  });
});
