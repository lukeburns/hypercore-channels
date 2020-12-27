# hypercore-channels

```js
const { crypto, readable, writable } = require('hypercore-channels')
const hypercore = require('hypercore')

const alice = hypercore('./alice', { crypto })
const bob = hypercore('./bob', { crypto })

// Bob can write secret love letters to Alice on the hypercore:
const lettersToAlice = hypercore('./to_alice', writable('love letters', bob.secretKey, alice.key))

// Alice can read secret love letters from Bob on the hypercore:
const lettersFromBob = hypercore('./from_bob', readable('love letters', bob.key, alice.secretKey))
```

See `example.js` for complete working example.

#### `const { key, crypto } = readable(bytes, publicKey, [secretKey])`

Derive a new public key from bytes, a public key, and optionally a secret key. If passed a secret key, will perform Diffie-Hellmann and concatenate common secret to bytes.

#### `const { secretKey, crypto } = writable(bytes, secretKey, [publicKey])`

Derive a new secret key from bytes, a secret key, and optionally a foreign public key. If passed a public key, will perform Diffie-Hellmann and concatenate common secret to bytes.

#### `crypto`

`crypto` is an object that should be passed to hypercore options.

```
{
    keyPair(),
    sign(message, secretKey),
    verify(message, signature, publicKey),
    publicKeySize,
    secretKeySize,
    signatureSize,
    signatureType
}
```