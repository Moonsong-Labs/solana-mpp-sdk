import { Method, Receipt, Store } from 'mppx'
import { findAssociatedTokenPda } from '@solana-program/token'
import { address } from '@solana/kit'
import * as Methods from '../Methods.js'
import {
  TOKEN_PROGRAM,
  TOKEN_2022_PROGRAM,
  DEFAULT_RPC_URLS,
} from '../constants.js'

/**
 * Creates a Solana `charge` method for usage on the server.
 *
 * Generates a unique reference for each payment challenge. Verifies payment by
 * fetching the transaction on-chain and checking that the transfer matches the
 * expected amount, recipient, and token mint.
 *
 * @example
 * ```ts
 * import { Mppx, solana } from 'solana-mpp-sdk/server'
 *
 * const mppx = Mppx.create({
 *   methods: [solana.charge({
 *     recipient: 'RecipientPubkey...',
 *     splToken: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
 *     decimals: 6,
 *     network: 'devnet',
 *   })],
 * })
 *
 * export async function handler(request: Request) {
 *   const result = await mppx.charge({ amount: '1000000', currency: 'USDC' })(request)
 *   if (result.status === 402) return result.challenge
 *   return result.withReceipt(Response.json({ data: '...' }))
 * }
 * ```
 */
export function charge(parameters: charge.Parameters) {
  const {
    recipient,
    splToken,
    decimals,
    tokenProgram = TOKEN_PROGRAM,
    network = 'mainnet-beta',
    store = Store.memory(),
  } = parameters

  const rpcUrl =
    parameters.rpcUrl ??
    DEFAULT_RPC_URLS[network] ??
    DEFAULT_RPC_URLS['mainnet-beta']

  if (splToken && decimals === undefined) {
    throw new Error('decimals is required when splToken is set')
  }

  return Method.toServer(Methods.charge, {
    defaults: {
      currency: splToken ? 'token' : 'SOL',
      methodDetails: {
        recipient: '',
        reference: '',
      },
    },

    async request({ credential, request }) {
      if (credential) {
        return credential.challenge.request as typeof request
      }

      const reference = crypto.randomUUID()

      return {
        ...request,
        methodDetails: {
          recipient,
          reference,
          network,
          ...(splToken
            ? { splToken, decimals, tokenProgram }
            : {}),
        },
      }
    },

    async verify({ credential }) {
      const { signature } = credential.payload
      const challenge = credential.challenge.request
      const expectedAmount = challenge.amount

      // Replay prevention: reject already-consumed transaction signatures.
      const consumedKey = `solana-charge:consumed:${signature}`
      if (await store.get(consumedKey)) {
        throw new Error('Transaction signature already consumed')
      }

      // Fetch and verify the transaction on-chain.
      const tx = await fetchTransaction(rpcUrl, signature)
      if (!tx) throw new Error('Transaction not found or not yet confirmed')
      if (tx.meta?.err) throw new Error('Transaction failed on-chain')

      const instructions = tx.transaction.message.instructions as ParsedInstruction[]

      if (challenge.methodDetails.splToken) {
        // ── SPL token transfer verification ──
        const transfer = instructions.find(
          (ix) =>
            ix.parsed?.type === 'transferChecked' &&
            (ix.programId === TOKEN_PROGRAM ||
              ix.programId === TOKEN_2022_PROGRAM),
        )
        if (!transfer) {
          throw new Error('No TransferChecked instruction found in transaction')
        }

        const info = transfer.parsed!.info
        if (info.mint !== challenge.methodDetails.splToken) {
          throw new Error(
            `Token mint mismatch: expected ${challenge.methodDetails.splToken}, got ${info.mint}`,
          )
        }
        if (info.tokenAmount.amount !== expectedAmount) {
          throw new Error(
            `Amount mismatch: expected ${expectedAmount}, got ${info.tokenAmount.amount}`,
          )
        }

        // Verify destination ATA belongs to the expected recipient.
        const expectedTokenProgram =
          challenge.methodDetails.tokenProgram || TOKEN_PROGRAM
        const [expectedAta] = await findAssociatedTokenPda({
          owner: address(recipient),
          mint: address(challenge.methodDetails.splToken),
          tokenProgram: address(expectedTokenProgram),
        })
        if (info.destination !== expectedAta) {
          throw new Error(
            'Destination token account does not belong to expected recipient',
          )
        }
      } else {
        // ── Native SOL transfer verification ──
        const transfer = instructions.find(
          (ix) =>
            ix.parsed?.type === 'transfer' && ix.program === 'system',
        )
        if (!transfer) {
          throw new Error('No system transfer instruction found in transaction')
        }

        const info = transfer.parsed!.info
        if (info.destination !== recipient) {
          throw new Error(
            `Recipient mismatch: expected ${recipient}, got ${info.destination}`,
          )
        }
        if (String(info.lamports) !== expectedAmount) {
          throw new Error(
            `Amount mismatch: expected ${expectedAmount} lamports, got ${info.lamports}`,
          )
        }
      }

      // Mark consumed to prevent replay.
      await store.put(consumedKey, true)

      return Receipt.from({
        method: 'solana',
        reference: signature,
        status: 'success',
        timestamp: new Date().toISOString(),
      })
    },
  })
}

// ── RPC helpers ──

type ParsedInstruction = {
  program?: string
  programId?: string
  parsed?: {
    type: string
    info: Record<string, any>
  }
}

async function fetchTransaction(
  rpcUrl: string,
  signature: string,
): Promise<any> {
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'getTransaction',
      params: [
        signature,
        {
          encoding: 'jsonParsed',
          commitment: 'confirmed',
          maxSupportedTransactionVersion: 0,
        },
      ],
    }),
  })
  const data = (await response.json()) as {
    result?: any
    error?: { message: string }
  }
  if (data.error) throw new Error(`RPC error: ${data.error.message}`)
  return data.result
}

export declare namespace charge {
  type Parameters = {
    /** Base58-encoded recipient public key that receives payments. */
    recipient: string
    /** SPL token mint address. If absent, payments are in native SOL. */
    splToken?: string
    /** Token decimals (required when splToken is set). */
    decimals?: number
    /** Token program address. Defaults to TOKEN_PROGRAM. Set to TOKEN_2022_PROGRAM for Token-2022 mints. */
    tokenProgram?: string
    /** Solana network. Defaults to 'mainnet-beta'. */
    network?: 'mainnet-beta' | 'devnet' | 'localnet'
    /** Custom RPC URL. Defaults to public RPC for the selected network. */
    rpcUrl?: string
    /**
     * Pluggable key-value store for consumed-signature tracking (replay prevention).
     * Defaults to in-memory. Use a persistent store in production.
     */
    store?: Store.Store
  }
}
