const sodium = require('sodium-native')
const { sign, verify, keyPair } = require('hypercore-crypto')

const one = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
one.fill(0)
one[0] = 1

function writable (bytes, secretKey, publicKey) {
  if (typeof bytes === 'string') bytes = Buffer.from(bytes)
  if (typeof secretKey === 'string') secretKey = Buffer.from(secretKey, 'hex')
  if (typeof publicKey === 'string') publicKey = Buffer.from(publicKey, 'hex')

  if (secretKey && publicKey) {
    const sharedPoint = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
    const sharedBytes = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    const sharedScalar = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    sodium.crypto_scalarmult_ristretto255(sharedPoint, secretKey, publicKey)
    sodium.crypto_generichash(sharedBytes, bytes, sharedPoint)
    bytesToScalar(sharedScalar, sharedBytes)

    const newSecretKey = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    sodium.crypto_core_ristretto255_scalar_mul(newSecretKey, sharedScalar, secretKey)

    const newPublicKey = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
    sodium.crypto_scalarmult_ristretto255_base(newPublicKey, newSecretKey)

    return {
      secretKey: newSecretKey,
      key: newPublicKey,
      crypto
    }
  } else if (!publicKey) {
    const scalarBytes = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    const scalar = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    sodium.crypto_generichash(scalarBytes, bytes)
    bytesToScalar(scalar, scalarBytes)

    const newSecretKey = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    sodium.crypto_core_ristretto255_scalar_mul(newSecretKey, scalar, secretKey)

    const newPublicKey = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
    sodium.crypto_scalarmult_ristretto255_base(newPublicKey, newSecretKey) // (sh * sk) * g

    return {
      secretKey: newSecretKey,
      key: newPublicKey,
      crypto
    }
  } else {
    return bytes
  }
}

function readable (bytes, publicKey, secretKey) {
  if (typeof bytes === 'string') bytes = Buffer.from(bytes)
  if (typeof secretKey === 'string') secretKey = Buffer.from(secretKey, 'hex')
  if (typeof publicKey === 'string') publicKey = Buffer.from(publicKey, 'hex')

  if (secretKey && publicKey) {
    const sharedPoint = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
    const sharedBytes = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    const sharedScalar = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    sodium.crypto_scalarmult_ristretto255(sharedPoint, secretKey, publicKey)
    sodium.crypto_generichash(sharedBytes, bytes, sharedPoint)
    bytesToScalar(sharedScalar, sharedBytes)

    const newPublicKey = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
    sodium.crypto_scalarmult_ristretto255(newPublicKey, sharedScalar, publicKey)

    return {
      key: newPublicKey,
      crypto
    }
  } else if (!secretKey) {
    const hashedBytes = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    const scalar = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    sodium.crypto_generichash(hashedBytes, bytes)
    bytesToScalar(scalar, hashedBytes)

    const newPublicKey = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
    sodium.crypto_scalarmult_ristretto255(newPublicKey, scalar, publicKey) // sh * (sk * g)

    return {
      key: newPublicKey,
      crypto
    }
  } else {
    return bytes
  }
}

const crypto = {
  publicKeySize: sodium.crypto_core_ristretto255_BYTES,
  secretKeySize: sodium.crypto_core_ristretto255_SCALARBYTES,
  signatureSize: 2 * sodium.crypto_core_ristretto255_SCALARBYTES,
  signatureType: 'ristretto255',
  sign (data, sk, cb) {
    return cb ? cb(null, sign(data, sk)) : sign(data, sk)
  },
  verify (data, sig, pk, cb) {
    return cb ? cb(null, verify(data, sig, pk)) : verify(data, sig, pk)
  },
  keyPair
}

module.exports = {
  writable,
  readable,
  crypto
}

function bytesToScalar (buf, bytes) {
  sodium.crypto_core_ristretto255_scalar_mul(buf, one, bytes)
}
