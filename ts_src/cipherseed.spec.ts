import { CipherSeed } from './cipherseed';

const mnemonic =
  'above judge emerge veteran reform crunch system all ' +
  'snap please shoulder vault hurt city quarter cover enlist ' +
  'swear success suggest drink wagon enrich body';
const entropy = Buffer.from('81b637d86359e6960de795e41e0b4cfd', 'hex');

describe('CipherSeed', () => {
  let cSeed: CipherSeed;
  it('should decode from mnemonic', () => {
    cSeed = CipherSeed.fromMnemonic(mnemonic);
    expect(cSeed.entropy).toEqual(entropy);
  });
  it('should encode to the same mnemonic', () => {
    const newMnemonic = cSeed.toMnemonic();
    expect(newMnemonic).toEqual(mnemonic);
  });
});
