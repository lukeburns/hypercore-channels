const { crypto, writable, readable } = require('./')
const ram = require('random-access-memory')
const hypercore = require('hypercore')

// private channel
const alice = crypto.keyPair()
const bob = crypto.keyPair()
console.log(`Alice: ${alice.secretKey.toString('hex')}`)
console.log(`Bob: ${bob.secretKey.toString('hex')}`)

const lettersFromBob = hypercore(ram, readable('love letters', bob.publicKey, alice.secretKey))
const lettersToAlice = hypercore(ram, writable('love letters', bob.secretKey, alice.publicKey))
console.log(`\nAlice's inbox: ${lettersFromBob.key.toString('hex')}`)
console.log(`Bob's key to inbox: ${lettersToAlice.secretKey.toString('hex')}\n`)

const as = lettersFromBob.replicate(false)
const bs = lettersToAlice.replicate(true)
as.pipe(bs).pipe(as).on('end', function () {
  // alice reads letters from bob
  console.log('Messages from Bob:')
  lettersFromBob.createReadStream()
    .on('data', x => console.log(x.toString()))
    .on('end', console.log.bind(console, '\n(end)'))
})

// bob writes letters to alice
lettersToAlice.append('my dearest alice...')
lettersToAlice.append(`you + me = ${Buffer.from('love').toString('hex')}`)
lettersToAlice.append('love bob')
lettersToAlice.flush(function () {
  console.log('Bob appended 3 blocks, %d in total (%d bytes)\n', lettersToAlice.length, lettersToAlice.byteLength)
})
