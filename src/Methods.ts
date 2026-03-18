import { Method, z } from 'mppx'

/**
 * Solana charge method — shared schema used by both server and client.
 *
 * The challenge request carries a recipient address and amount so the client
 * knows exactly what to pay. The credential payload carries the transaction
 * signature, which the server verifies on-chain via RPC.
 */
export const charge = Method.from({
  intent: 'charge',
  name: 'solana',
  schema: {
    credential: {
      payload: z.object({
        /** Base58-encoded transaction signature proving payment. */
        signature: z.string(),
      }),
    },
    request: z.object({
      /** Amount in smallest unit (lamports for SOL, base units for SPL tokens). */
      amount: z.string(),
      currency: z.optional(z.string()),
      description: z.optional(z.string()),
      methodDetails: z.object({
        /** Base58-encoded recipient public key. */
        recipient: z.string(),
        /** Unique reference ID for this charge (server-generated, used for tracking). */
        reference: z.string(),
        /** Solana network: mainnet-beta, devnet, or localnet. */
        network: z.optional(z.string()),
        /** SPL token mint address. If absent, payment is in native SOL. */
        splToken: z.optional(z.string()),
        /** Token decimals (required for SPL token transfers). */
        decimals: z.optional(z.number()),
        /** Token program address (TOKEN_PROGRAM or TOKEN_2022_PROGRAM). Defaults to TOKEN_PROGRAM. */
        tokenProgram: z.optional(z.string()),
      }),
    }),
  },
})
