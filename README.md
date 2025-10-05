# hypercore-channels

Ristretto255-based secure communication channels for Hypercore applications.

## Features

- **Private Channels**: ECDH-based secure communication between parties
- **Public Namespaces**: Public-key-only namespacing for broadcasting
- **Hierarchical Organization**: Nested namespace structures
- **Cryptographic Verification**: Schnorr signatures with ristretto255

## Quick Example

```js
import { writable, readable } from './index.js'
import crypto from 'hypercore-crypto'

// Generate key pairs
const alice = crypto.keyPair()
const bob = crypto.keyPair()

// Private channel: Bob can write to Alice
const lettersToAlice = writable('love letters', bob.secretKey, alice.publicKey)
const lettersFromBob = readable('love letters', bob.publicKey, alice.secretKey)

// Public namespace: Anyone can derive Alice's blog
const aliceBlog = writable('alice-blog', alice.secretKey)
const publicBlog = readable('alice-blog', alice.publicKey)

console.log('Private channel keys match:', lettersToAlice.key.equals(lettersFromBob.key))
console.log('Public namespace keys match:', aliceBlog.key.equals(publicBlog.key))
```

## API

### `writable(context, secretKey, [publicKey])`

Creates a writable channel. If `publicKey` is provided, performs ECDH for private communication.

### `readable(context, publicKey, [secretKey])`

Creates a readable channel. If `secretKey` is provided, performs ECDH for private communication.

### Modes

- **Private Channel**: `writable(context, secretKey, publicKey)` + `readable(context, publicKey, secretKey)`
- **Public Namespace**: `writable(context, secretKey)` + `readable(context, publicKey)`
- **Personal Namespace**: `writable(context, secretKey)` only