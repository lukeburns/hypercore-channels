const { crypto, writable, readable } = require('.')
const ram = require('random-access-memory')
const Hypercore = require('hypercore');

(async () => {
  const alice = crypto.keyPair()
  const bob = crypto.keyPair()
  console.log(`Alice: ${alice.secretKey.toString('hex')}`)
  console.log(`Bob: ${bob.secretKey.toString('hex')}`)

  // public channel
  const alicesCats = new Hypercore(ram, readable('cats', alice.publicKey))
  const myCats = new Hypercore(ram, writable('cats', alice.secretKey))
  await alicesCats.ready()
  await myCats.ready()
  console.log(alicesCats.key)
  console.log(myCats.key)

  // private channel

  const lettersFromBobKeyPair = readable('love letters', bob.publicKey, alice.secretKey)
  const lettersToAliceKeyPair = writable('love letters', bob.secretKey, alice.publicKey)
  const lettersFromBob = new Hypercore(ram, lettersFromBobKeyPair)
  const lettersToAlice = new Hypercore(ram, lettersToAliceKeyPair)
  await lettersFromBob.ready()
  await lettersToAlice.ready()
  console.log(`\nAlice's inbox: ${lettersFromBobKeyPair.key.toString('hex')}`)
  console.log(`Bob's secret key to inbox: ${lettersToAliceKeyPair.secretKey.toString('hex')}\n`)

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
  await lettersToAlice.append('my dearest alice...')
  await lettersToAlice.append(`you + me = ${Buffer.from('love').toString('hex')}`)
  await lettersToAlice.append('love bob')
  console.log('Bob appended 3 blocks, %d in total (%d bytes)\n', lettersToAlice.length, lettersToAlice.byteLength)
})()
