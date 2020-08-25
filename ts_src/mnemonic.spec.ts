import { mnemonicFromBytes, mnemonicToBytes } from './mnemonic';

const bytes = Buffer.from(
  '008f1522f99b4469f73033cd54cf1bf8e6fc52ebd98c4adb73616c7431ec92c0c7',
  'hex',
);
const mnemonic =
  'above judge emerge veteran reform crunch system all ' +
  'snap please shoulder vault hurt city quarter cover enlist ' +
  'swear success suggest drink wagon enrich body';
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
