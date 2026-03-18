/**
 * Example: Solana MPP client that pays for API access on devnet.
 *
 * Usage:
 *   SECRET_KEY=base58EncodedKeypair npx tsx examples/client.ts
 */
import { Mppx, solana } from '../src/client/index.js'
import { createKeyPairSignerFromBytes, getBase58Encoder } from '@solana/kit'

const secretKey = process.env.SECRET_KEY
if (!secretKey) {
  console.error('Set SECRET_KEY env var to a base58-encoded Solana keypair')
  process.exit(1)
}

const keyBytes = getBase58Encoder().encode(secretKey)
const signer = await createKeyPairSignerFromBytes(keyBytes)

console.log(`Client wallet: ${signer.address}`)

const method = solana.charge({
  signer,
  rpcUrl: 'https://api.devnet.solana.com',
  onProgress(event) {
    switch (event.type) {
      case 'challenge':
        console.log(
          `Payment required: ${event.amount} ${event.splToken ? 'tokens' : 'lamports'} to ${event.recipient}`,
        )
        break
      case 'paying':
        console.log('Sending transaction...')
        break
      case 'confirming':
        console.log(`Confirming: ${event.signature}`)
        break
      case 'paid':
        console.log(`Confirmed: ${event.signature}`)
        break
    }
  },
})

const mppx = Mppx.create({ methods: [method] })

const response = await mppx.fetch('http://localhost:3000/weather')
console.log('Response:', await response.json())
