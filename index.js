import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js'

// Ristretto255 constants
const SCALAR_BYTES = 32
const POINT_BYTES = 32

function writable (bytes = '', secretKey, publicKey) {
  if (!secretKey) throw new Error('writable channel requires a secret key')

  if (typeof bytes === 'string') bytes = Buffer.from(bytes)
  if (typeof secretKey === 'string') secretKey = Buffer.from(secretKey, 'hex')
  if (typeof publicKey === 'string') publicKey = Buffer.from(publicKey, 'hex')

  if (secretKey && publicKey) {
    // Extract private key from 64-byte secret key (first 32 bytes)
    const privateKey = secretKey.subarray(0, 32)
    
    // Perform ECDH to get shared secret
    const secretKeyScalar = ristretto255.Point.Fn.fromBytes(privateKey)
    const publicKeyPoint = ristretto255.Point.fromBytes(publicKey)
    const sharedPoint = publicKeyPoint.multiply(secretKeyScalar)
    const sharedPointBytes = Buffer.from(sharedPoint.toBytes())
    
    // Hash bytes + shared point to get scalar
    const hash = sha256.create()
    hash.update(bytes)
    hash.update(sharedPointBytes)
    const sharedScalar = ristretto255_hasher.hashToScalar(hash.digest())
    
    // Derive new secret key: sharedScalar * secretKey
    const newSecretKeyScalar = ristretto255.Point.Fn.mul(sharedScalar, secretKeyScalar)
    const newSecretKey = Buffer.from(ristretto255.Point.Fn.toBytes(newSecretKeyScalar))
    
    // Derive new public key: newSecretKey * G
    const newPublicKeyPoint = ristretto255.Point.BASE.multiply(newSecretKeyScalar)
    const newPublicKey = Buffer.from(newPublicKeyPoint.toBytes())

    return {
      secretKey: newSecretKey,
      key: newPublicKey
    }
  } else if (!publicKey) {
    // Extract private key from 64-byte secret key (first 32 bytes)
    const privateKey = secretKey.subarray(0, 32)
    
    // Hash bytes to get scalar
    const hash = sha256.create()
    hash.update(bytes)
    const scalar = ristretto255_hasher.hashToScalar(hash.digest())
    
    // Derive new secret key: scalar * secretKey
    const secretKeyScalar = ristretto255.Point.Fn.fromBytes(privateKey)
    const newSecretKeyScalar = ristretto255.Point.Fn.mul(scalar, secretKeyScalar)
    const newSecretKey = Buffer.from(ristretto255.Point.Fn.toBytes(newSecretKeyScalar))
    
    // Derive new public key: newSecretKey * G
    const newPublicKeyPoint = ristretto255.Point.BASE.multiply(newSecretKeyScalar)
    const newPublicKey = Buffer.from(newPublicKeyPoint.toBytes())

    return {
      secretKey: newSecretKey,
      key: newPublicKey
    }
  } else {
    return bytes
  }
}

function readable (bytes = '', publicKey, secretKey) {
  if (!publicKey) throw new Error('readable channel requires a public key')

  if (typeof bytes === 'string') bytes = Buffer.from(bytes)
  if (typeof secretKey === 'string') secretKey = Buffer.from(secretKey, 'hex')
  if (typeof publicKey === 'string') publicKey = Buffer.from(publicKey, 'hex')

  if (secretKey && publicKey) {
    // Extract private key from 64-byte secret key (first 32 bytes)
    const privateKey = secretKey.subarray(0, 32)
    
    // Perform ECDH to get shared secret
    const secretKeyScalar = ristretto255.Point.Fn.fromBytes(privateKey)
    const publicKeyPoint = ristretto255.Point.fromBytes(publicKey)
    const sharedPoint = publicKeyPoint.multiply(secretKeyScalar)
    const sharedPointBytes = Buffer.from(sharedPoint.toBytes())
    
    // Hash bytes + shared point to get scalar
    const hash = sha256.create()
    hash.update(bytes)
    hash.update(sharedPointBytes)
    const sharedScalar = ristretto255_hasher.hashToScalar(hash.digest())
    
    // Derive new public key: sharedScalar * publicKey
    const newPublicKeyPoint = publicKeyPoint.multiply(sharedScalar)
    const newPublicKey = Buffer.from(newPublicKeyPoint.toBytes())

    return {
      key: newPublicKey
    }
  } else if (!secretKey) {
    // Hash bytes to get scalar
    const hash = sha256.create()
    hash.update(bytes)
    const scalar = ristretto255_hasher.hashToScalar(hash.digest())
    
    // Derive new public key: scalar * publicKey
    const publicKeyPoint = ristretto255.Point.fromBytes(publicKey)
    const newPublicKeyPoint = publicKeyPoint.multiply(scalar)
    const newPublicKey = Buffer.from(newPublicKeyPoint.toBytes())

    return {
      key: newPublicKey
    }
  } else {
    return bytes
  }
}


export {
  writable,
  readable
}
