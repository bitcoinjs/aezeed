import { mnemonicFromBytes, mnemonicToBytes } from './mnemonic';

const bytes = Buffer.from(
  '000a9f416caaa8988c1848a053fc14f6bb815981eea3195b481d4efe3eb8846b3f',
  'hex',
);

// This is a valid aezeed v0, a valid BIP39, and a valid Electrum v2 segwit seed
const mnemonic =
  'abandon female space sun pride era corn animal park paper ' +
  'ahead uniform retreat proud amateur stamp bone surge also ' +
  'over token fox balance gun';
const wrongLength =
  'above judge emerge veteran reform crunch system all ' +
  'snap please shoulder vault hurt city quarter cover enlist ' +
  'swear success suggest drink wagon enrich body body';
const wrongWord =
  'zzzzz judge emerge veteran reform crunch system all ' +
  'snap please shoulder vault hurt city quarter cover enlist ' +
  'swear success suggest drink wagon enrich body';

describe('mnemonic', () => {
  it('should convert mnemonic to bytes', () => {
    expect(mnemonicToBytes(mnemonic)).toEqual(bytes);
  });
  it('should convert bytes to mnemonic', () => {
    expect(mnemonicFromBytes(bytes)).toEqual(mnemonic);
  });
  it('should fail with wrong word count', () => {
    expect(() => {
      mnemonicToBytes(wrongLength);
    }).toThrow(/^Invalid Mnemonic$/);
  });
  it('should fail with unknown word', () => {
    expect(() => {
      mnemonicToBytes(wrongWord);
    }).toThrow(/^Invalid Mnemonic$/);
  });
});
