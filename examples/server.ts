/**
 * Example: Solana MPP server that charges 1 USDC per request on devnet.
 *
 * Usage:
 *   RECIPIENT=YourWalletPubkey npx tsx examples/server.ts
 */
import { createServer } from 'node:http'
import { Mppx, solana } from '../src/server/index.js'

const recipient = process.env.RECIPIENT!
if (!recipient) {
  console.error('Set RECIPIENT env var to your Solana wallet public key')
  process.exit(1)
}

// USDC on devnet
const USDC_DEVNET = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'

const mppx = Mppx.create({
  methods: [
    solana.charge({
      recipient,
      splToken: USDC_DEVNET,
      decimals: 6,
      network: 'devnet',
    }),
  ],
})

const server = createServer(async (req, res) => {
  const url = new URL(req.url!, `http://${req.headers.host}`)

  if (url.pathname === '/weather') {
    // Convert Node request to Web Request
    const headers = new Headers()
    for (const [key, value] of Object.entries(req.headers)) {
      if (value) headers.set(key, Array.isArray(value) ? value[0] : value)
    }
    const request = new Request(url, { method: req.method, headers })

    const result = await mppx.charge({
      amount: '1000000', // 1 USDC
      currency: 'USDC',
      description: 'Weather API access',
    })(request)

    if (result.status === 402) {
      const challenge = result.challenge as Response
      res.writeHead(challenge.status, Object.fromEntries(challenge.headers))
      res.end(await challenge.text())
      return
    }

    const response = result.withReceipt(
      Response.json({
        location: 'San Francisco',
        temperature: 18,
        conditions: 'Foggy',
      }),
    ) as Response

    res.writeHead(response.status, Object.fromEntries(response.headers))
    res.end(await response.text())
    return
  }

  res.writeHead(404)
  res.end('Not found')
})

server.listen(3000, () => {
  console.log('Server running on http://localhost:3000')
  console.log(`Accepting USDC payments to ${recipient}`)
})
