import { Credential, Method } from 'mppx'
import {
  createSolanaRpc,
  pipe,
  createTransactionMessage,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  setTransactionMessageComputeUnitLimit,
  setTransactionMessageComputeUnitPrice,
  appendTransactionMessageInstructions,
  signTransactionMessageWithSigners,
  getBase64EncodedWireTransaction,
  address,
  AccountRole,
  type TransactionSigner,
  type Instruction,
} from '@solana/kit'
import { getTransferSolInstruction } from '@solana-program/system'
import {
  getTransferCheckedInstruction,
  findAssociatedTokenPda,
} from '@solana-program/token'
import * as Methods from '../Methods.js'
import {
  TOKEN_PROGRAM,
  ASSOCIATED_TOKEN_PROGRAM,
  DEFAULT_RPC_URLS,
} from '../constants.js'

/**
 * Creates a Solana `charge` method for usage on the client.
 *
 * Intercepts 402 responses, builds and sends a Solana transaction to pay the
 * requested amount, and retries with the transaction signature as credential.
 *
 * The `signer` parameter accepts any `TransactionSigner` from `@solana/kit`,
 * which is compatible with ConnectorKit's `useTransactionSigner()` hook and
 * with `createKeyPairSignerFromBytes()` for headless/server usage.
 *
 * @example
 * ```ts
 * import { Mppx, solana } from 'solana-mpp-sdk/client'
 *
 * const method = solana.charge({ signer, rpcUrl: 'https://api.devnet.solana.com' })
 * const mppx = Mppx.create({ methods: [method] })
 *
 * const response = await mppx.fetch('https://api.example.com/paid-content')
 * console.log(await response.json())
 * ```
 */
export function charge(parameters: charge.Parameters) {
  const { signer, onProgress } = parameters

  const method = Method.toClient(Methods.charge, {
    async createCredential({ challenge }) {
      const { amount, methodDetails } = challenge.request
      const {
        recipient,
        network,
        splToken,
        decimals,
        tokenProgram: tokenProgramAddr,
      } = methodDetails

      const rpcUrl =
        parameters.rpcUrl ??
        DEFAULT_RPC_URLS[network || 'mainnet-beta'] ??
        DEFAULT_RPC_URLS['mainnet-beta']
      const rpc = createSolanaRpc(rpcUrl)

      onProgress?.({
        type: 'challenge',
        recipient,
        amount,
        splToken: splToken || undefined,
      })

      // Build transfer instructions.
      const instructions: Instruction[] = []

      if (splToken) {
        // ── SPL token transfer ──
        const mint = address(splToken)
        const tokenProg = address(tokenProgramAddr || TOKEN_PROGRAM)

        const [sourceAta] = await findAssociatedTokenPda({
          owner: signer.address,
          mint,
          tokenProgram: tokenProg,
        })

        const [destAta] = await findAssociatedTokenPda({
          owner: address(recipient),
          mint,
          tokenProgram: tokenProg,
        })

        // Create destination ATA if it doesn't exist (idempotent).
        instructions.push(
          createAssociatedTokenAccountIdempotent(
            signer,
            address(recipient),
            mint,
            destAta,
            tokenProg,
          ),
        )

        instructions.push(
          getTransferCheckedInstruction(
            {
              source: sourceAta,
              mint,
              destination: destAta,
              authority: signer,
              amount: BigInt(amount),
              decimals: decimals ?? 6,
            },
            { programAddress: tokenProg },
          ),
        )
      } else {
        // ── Native SOL transfer ──
        instructions.push(
          getTransferSolInstruction({
            source: signer,
            destination: address(recipient),
            amount: BigInt(amount),
          }),
        )
      }

      onProgress?.({ type: 'paying' })

      // Build, sign, and send the transaction.
      const { value: latestBlockhash } = await rpc
        .getLatestBlockhash()
        .send()

      const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        (msg) => setTransactionMessageFeePayerSigner(signer, msg),
        (msg) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, msg),
        (msg) => setTransactionMessageComputeUnitLimit(50_000, msg),
        (msg) => setTransactionMessageComputeUnitPrice(1n, msg),
        (msg) => appendTransactionMessageInstructions(instructions, msg),
      )

      const signedTx = await signTransactionMessageWithSigners(txMessage)
      const encodedTx = getBase64EncodedWireTransaction(signedTx)

      const signature = await rpc
        .sendTransaction(encodedTx, {
          encoding: 'base64',
          skipPreflight: false,
        })
        .send()

      onProgress?.({ type: 'confirming', signature })

      // Wait for on-chain confirmation before returning the credential.
      await confirmTransaction(rpc, signature)

      onProgress?.({ type: 'paid', signature })

      return Credential.serialize({
        challenge,
        payload: { signature },
      })
    },
  })

  return method
}

// ── Helpers ──

/**
 * Creates an Associated Token Account using the idempotent instruction
 * (CreateIdempotent = discriminator 1). This is a no-op if the ATA exists.
 */
function createAssociatedTokenAccountIdempotent(
  payer: TransactionSigner,
  owner: ReturnType<typeof address>,
  mint: ReturnType<typeof address>,
  ata: ReturnType<typeof address>,
  tokenProgram: ReturnType<typeof address>,
): Instruction {
  return {
    programAddress: address(ASSOCIATED_TOKEN_PROGRAM),
    accounts: [
      { address: payer.address, role: AccountRole.WRITABLE_SIGNER, signer: payer } as any,
      { address: ata, role: AccountRole.WRITABLE },
      { address: owner, role: AccountRole.READONLY },
      { address: mint, role: AccountRole.READONLY },
      { address: address('11111111111111111111111111111111'), role: AccountRole.READONLY },
      { address: tokenProgram, role: AccountRole.READONLY },
    ],
    data: new Uint8Array([1]), // CreateIdempotent discriminator
  }
}

/**
 * Polls for transaction confirmation via getSignatureStatuses.
 * Avoids requiring WebSocket subscriptions.
 */
async function confirmTransaction(
  rpc: ReturnType<typeof createSolanaRpc>,
  signature: string,
  timeoutMs = 30_000,
) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const { value } = await rpc
      .getSignatureStatuses([signature] as any)
      .send()
    const status = value[0]
    if (status) {
      if (status.err) {
        throw new Error(
          `Transaction failed: ${JSON.stringify(status.err)}`,
        )
      }
      if (
        status.confirmationStatus === 'confirmed' ||
        status.confirmationStatus === 'finalized'
      ) {
        return
      }
    }
    await new Promise((r) => setTimeout(r, 2_000))
  }
  throw new Error('Transaction confirmation timeout')
}

export declare namespace charge {
  type Parameters = {
    /**
     * Solana transaction signer. Compatible with:
     * - ConnectorKit's `useTransactionSigner()` hook
     * - `createKeyPairSignerFromBytes()` from `@solana/kit` for headless usage
     * - Any `TransactionSigner` implementation
     */
    signer: TransactionSigner
    /** Custom RPC URL. If not set, inferred from the challenge's network field. */
    rpcUrl?: string
    /** Called at each step of the payment process. */
    onProgress?: (event: ProgressEvent) => void
  }

  type ProgressEvent =
    | { type: 'challenge'; recipient: string; amount: string; splToken?: string }
    | { type: 'paying' }
    | { type: 'confirming'; signature: string }
    | { type: 'paid'; signature: string }
}
