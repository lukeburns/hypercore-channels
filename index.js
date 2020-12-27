const sodium = require('sodium-native')

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

function keyPair () {
  const sk = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const pk = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  sodium.crypto_core_ristretto255_scalar_random(sk)
  sodium.crypto_scalarmult_ristretto255_base(pk, sk)
  return {
    publicKey: pk,
    secretKey: sk
  }
}

function sign (m, sk) {
  if (typeof m === 'string') m = Buffer.from(m)
  if (typeof sk === 'string') sk = Buffer.from(sk, 'hex')
  const k = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const eBytes = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const e = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const xe = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const s = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const r = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  sodium.crypto_core_ristretto255_scalar_random(k) // k
  sodium.crypto_scalarmult_ristretto255_base(r, k) // r = k*g
  sodium.crypto_generichash(eBytes, Buffer.concat([r, m])) // e = hash(r|m)
  bytesToScalar(e, eBytes)
  sodium.crypto_core_ristretto255_scalar_mul(xe, sk, e) // xe = e*sk
  sodium.crypto_core_ristretto255_scalar_sub(s, k, xe) // s = k - esk
  return Buffer.concat([s, e]) // sig = (s,e)
}

function verify (m, sig, pk) {
  if (typeof m === 'string') m = Buffer.from(m)
  if (typeof sig === 'string') sig = Buffer.from(sig, 'hex')
  if (typeof pk === 'string') pk = Buffer.from(pk, 'hex')
  const s = sig.slice(0, sodium.crypto_core_ristretto255_SCALARBYTES)
  const e = sig.slice(sodium.crypto_core_ristretto255_SCALARBYTES, 2 * sodium.crypto_core_ristretto255_SCALARBYTES)
  const evBytes = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const ev = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const sg = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  const epk = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  const rv = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  sodium.crypto_scalarmult_ristretto255_base(sg, s) // sg = s*g
  sodium.crypto_scalarmult_ristretto255(epk, e, pk) // epk = e*pk
  sodium.crypto_core_ristretto255_add(rv, sg, epk) // rv = sg + epk = (k - e sk)g + epk = k g - e pk + e pk = k g
  sodium.crypto_generichash(evBytes, Buffer.concat([rv, m])) // e = hash(r|m)c
  bytesToScalar(ev, evBytes)
  return ev.equals(e)
}

function bytesToScalar (buf, bytes) {
  sodium.crypto_core_ristretto255_scalar_mul(buf, one, bytes)
}
