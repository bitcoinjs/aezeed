import { mocked } from 'ts-jest/utils';
import * as params from './params';
import { CipherSeed, daysSinceGenesis } from './cipherseed';
let lndVersion0TestVectors: Vector[];
let extraVersion0TestVectors: Vector[];

describe('CipherSeed', () => {
  // This is used for running the various vectors
  const runVector = (vector: Vector): void => {
    const birthday = daysSinceGenesis(vector.time);
    expect(birthday).toBe(vector.expectedBirthday);
    const seed = new CipherSeed(
      vector.entropy,
      vector.salt,
      vector.version,
      birthday,
    );
    const mnemonic = seed.toMnemonic(vector.password);
    expect(mnemonic).toBe(vector.expectedMnemonic);
  };

  // Actually run each vector
  it('should pass lnd vectors', () => {
    lndVersion0TestVectors.forEach(runVector);
  });
  it('should pass extra vectors', () => {
    extraVersion0TestVectors.forEach(runVector);
  });

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

// Mock the PARAMS to make them weaking, testing is faster.
// These mock params match LND (so we can test against their vectors)
jest.mock('./params');
const mockedParams = mocked(params, true);
mockedParams.PARAMS[0] = {
  n: 16,
  r: 8,
  p: 1,
};

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

// From LND repository
// ./aezeed/cipherseed_test.go#L23-L63
// at commit 63bd8e77760f77650e854e69cff5b8a4acc18862

const testEntropy = Buffer.from('81b637d86359e6960de795e41e0b4cfd', 'hex');
const testSalt = Buffer.from([0x73, 0x61, 0x6c, 0x74, 0x31]);
const BitcoinGenesisDate = new Date('2009-01-03T18:15:05.000Z');
lndVersion0TestVectors = [
  {
    version: 0,
    time: BitcoinGenesisDate,
    entropy: testEntropy,
    salt: testSalt,
    password: undefined,
    expectedMnemonic:
      'ability liquid travel stem barely drastic pact cupboard apple thrive ' +
      'morning oak feature tissue couch old math inform success suggest drink ' +
      'motion know royal',
    expectedBirthday: 0,
  },
  {
    version: 0,
    time: new Date(1521799345000), // 03/23/2018 @ 10:02am (UTC)
    entropy: testEntropy,
    salt: testSalt,
    password: '!very_safe_55345_password*',
    expectedMnemonic:
      'able tree stool crush transfer cloud cross three profit outside hen ' +
      'citizen plate ride require leg siren drum success suggest drink ' +
      'require fiscal upgrade',
    expectedBirthday: 3365,
  },
];

extraVersion0TestVectors = [
  {
    version: 0,
    time: new Date(4062184705000), // 09/22/2098 @ 12:38:25am (UTC)
    entropy: testEntropy,
    salt: testSalt,
    password: 'LsD58g1jZH3dKsSpdaVa6J9Lxd',
    expectedMnemonic:
      'abandon spare anxiety dry resemble hub false behind bachelor van ' +
      'express chunk belt flat flash junior moon fatal success suggest ' +
      'drink share document thrive',
    expectedBirthday: 0x8000, // 0x8000 to make sure we handle unsigned properly
  },
];

interface Vector {
  version: number;
  time: Date;
  entropy: Buffer;
  salt: Buffer;
  password?: string;
  expectedMnemonic: string;
  expectedBirthday: number;
}
