# aezeed
A package for encoding, decoding, and generating mnemonics of the aezeed specification. (WIP)

# Example

* TypeScript types are available as well. commonjs example below.

```js
const { CipherSeed } = require('aezeed');
```

* You can also pass the 16 byte entropy and 5 byte salt as Buffers to the constructor.
* random() uses randombytes under the hood to generate the 21 random bytes needed.

```js
// Make a random seed and password protect it.
const mnemonic1 = CipherSeed.random().toMnemonic('strongPassword');
console.log(mnemonic1);

// Or no password protection (default password is 'aezeed' when not passed)
const mnemonic2 = CipherSeed.random().toMnemonic();
console.log(mnemonic2);
```

* You can decode mnemonics as well.
* `birthDate` is a Date object of the approximate day when the wallet was generated. (rounded down to the nearest 18:15:05 UTC (the time-of-day of the timestamp in the Bitcoin genesis block))
* `birthday` is a number, represents the number of days since the genesis block.
* `entropy` is the 16 bytes needed for generating the root key for the BIP32 HD key.

```js
// Decoding to get at the entropy and birthday values with password
const mnemonic3 =
  'able mix price funny host express lawsuit congress antique float pig ' +
  'exchange vapor drip wide cup style apple tumble verb fix blush tongue ' +
  'market';
const cipherSeed1 = CipherSeed.fromMnemonic(mnemonic3, 'strongPassword');
console.log(cipherSeed1.entropy);
// <Buffer fc 88 ea ad 1a 74 62 90 da bc 3b 58 39 9c e9 3f>
console.log(cipherSeed1.birthDate);
// <Date 2020-08-24T18:15:05.000Z>

// Without password
const mnemonic4 =
  'able concert slush lend olive cost wagon dawn board robot park snap ' +
  'dignity churn fiction quote shrimp hammer wing jump immune skill sunset ' +
  'west';
const cipherSeed2 = CipherSeed.fromMnemonic(mnemonic4);
console.log(cipherSeed2.entropy);
// <Buffer b0 c2 91 6c 06 4e da 9a ff ec 6e c4 63 81 e5 92>
console.log(cipherSeed2.birthDate);
// <Date 2020-08-24T18:15:05.000Z>
```
