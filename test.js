import { test } from 'brittle'
import { writable, readable } from './index.js'
import crypto from 'hypercore-crypto'

test('ristretto255 channels - key generation', (t) => {
  const alice = crypto.keyPair()
  const bob = crypto.keyPair()

  t.ok(alice.publicKey, 'Alice has public key')
  t.ok(alice.secretKey, 'Alice has secret key')
  t.ok(bob.publicKey, 'Bob has public key')
  t.ok(bob.secretKey, 'Bob has secret key')
  
  t.is(alice.publicKey.length, 32, 'Alice public key is 32 bytes')
  t.is(alice.secretKey.length, 64, 'Alice secret key is 64 bytes')
  t.is(bob.publicKey.length, 32, 'Bob public key is 32 bytes')
  t.is(bob.secretKey.length, 64, 'Bob secret key is 64 bytes')
})

test('ristretto255 channels - public channel (no ECDH)', (t) => {
  const alice = crypto.keyPair()
  
  const alicesCatsChannel = readable('cats', alice.publicKey)
  const myCatsChannel = writable('cats', alice.secretKey)

  t.ok(alicesCatsChannel.key, 'Alice\'s cats channel has key')
  t.ok(myCatsChannel.key, 'My cats channel has key')
  t.ok(alicesCatsChannel.key.equals(myCatsChannel.key), 'Public channel keys match')
  t.is(alicesCatsChannel.key.length, 32, 'Channel key is 32 bytes')
})

test('ristretto255 channels - private channel (with ECDH)', (t) => {
  const alice = crypto.keyPair()
  const bob = crypto.keyPair()
  
  const lettersFromBobChannel = readable('love letters', bob.publicKey, alice.secretKey)
  const lettersToAliceChannel = writable('love letters', bob.secretKey, alice.publicKey)

  t.ok(lettersFromBobChannel.key, 'Alice\'s inbox has key')
  t.ok(lettersToAliceChannel.key, 'Bob\'s outbox has key')
  t.ok(lettersFromBobChannel.key.equals(lettersToAliceChannel.key), 'Private channel keys match')
  t.is(lettersFromBobChannel.key.length, 32, 'Private channel key is 32 bytes')
})

test('ristretto255 channels - crypto operations', (t) => {
  const alice = crypto.keyPair()
  const message = Buffer.from('Hello from ristretto255!')
  
  const signature = crypto.sign(message, alice.secretKey)
  const isValid = crypto.verify(message, signature, alice.publicKey)

  t.ok(signature, 'Signature generated')
  t.is(signature.length, 64, 'Signature is 64 bytes')
  t.ok(isValid, 'Signature is valid')
})

test('ristretto255 channels - public namespace creation', (t) => {
  const alice = crypto.keyPair()
  
  const aliceBlog = writable('alice-blog', alice.secretKey)
  const publicBlog = readable('alice-blog', alice.publicKey)

  t.ok(aliceBlog.key, 'Alice\'s blog has key')
  t.ok(publicBlog.key, 'Public blog has key')
  t.ok(aliceBlog.key.equals(publicBlog.key), 'Public namespace keys match')
  t.is(aliceBlog.key.length, 32, 'Public namespace key is 32 bytes')
})

test('ristretto255 channels - hierarchical public namespaces', (t) => {
  const alice = crypto.keyPair()
  const namespaces = [
    'alice-blog:posts',
    'alice-blog:comments', 
    'alice-blog:metadata',
    'alice-blog:announcements'
  ]

  for (const namespace of namespaces) {
    const aliceNamespace = writable(namespace, alice.secretKey)
    const publicNamespace = readable(namespace, alice.publicKey)
    
    t.ok(aliceNamespace.key, `${namespace} - Alice's namespace has key`)
    t.ok(publicNamespace.key, `${namespace} - Public namespace has key`)
    t.ok(aliceNamespace.key.equals(publicNamespace.key), `${namespace} - Namespace keys match`)
    t.is(aliceNamespace.key.length, 32, `${namespace} - Namespace key is 32 bytes`)
  }
})

test('ristretto255 channels - public verification', (t) => {
  const alice = crypto.keyPair()
  const blogMessage = Buffer.from('Hello from Alice\'s public blog!')
  
  const blogSignature = crypto.sign(blogMessage, alice.secretKey)
  const blogIsValid = crypto.verify(blogMessage, blogSignature, alice.publicKey)

  t.ok(blogSignature, 'Blog signature generated')
  t.is(blogSignature.length, 64, 'Blog signature is 64 bytes')
  t.ok(blogIsValid, 'Blog signature is valid')
})

test('ristretto255 channels - deterministic key derivation', (t) => {
  const alice = crypto.keyPair()
  
  // Same context should always produce same keys
  const context1 = 'same-context'
  const context2 = 'same-context'
  const context3 = 'different-context'

  const key1a = readable(context1, alice.publicKey)
  const key1b = readable(context2, alice.publicKey)
  const key1c = readable(context3, alice.publicKey)

  t.ok(key1a.key.equals(key1b.key), 'Same context produces same key')
  t.not(key1a.key.equals(key1c.key), 'Different context produces different key')
})

test('ristretto255 channels - multiple private channels', (t) => {
  const alice = crypto.keyPair()
  const bob = crypto.keyPair()
  
  const channels = [
    'love-letters',
    'work-secrets', 
    'family-chat'
  ]

  for (const channel of channels) {
    const alicesChannel = readable(channel, bob.publicKey, alice.secretKey)
    const bobsChannel = writable(channel, bob.secretKey, alice.publicKey)
    
    t.ok(alicesChannel.key, `${channel} - Alice's channel has key`)
    t.ok(bobsChannel.key, `${channel} - Bob's channel has key`)
    t.ok(alicesChannel.key.equals(bobsChannel.key), `${channel} - Channel keys match`)
    t.is(alicesChannel.key.length, 32, `${channel} - Channel key is 32 bytes`)
  }
})
