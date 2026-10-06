"use client";

// Wallet Standard access (OL-C-24).
//
// The panel talks to the Wallet Standard feature API directly: `standard:connect`
// to pick an account and `solana:signTransaction` to sign the exact bytes the
// Admin API prepared. No keypair, seed phrase or private key ever enters the UI,
// and only the `solana:devnet` chain is accepted.
import { getWallets } from "@wallet-standard/app";
import type { Wallet, WalletAccount } from "@wallet-standard/base";

export const DEVNET_CHAIN = "solana:devnet";

export interface ConnectedWallet {
  walletName: string;
  address: string;
  account: WalletAccount;
  wallet: Wallet;
}

interface ConnectFeature {
  connect: (input?: { silent?: boolean }) => Promise<{ accounts: readonly WalletAccount[] }>;
}

interface SignTransactionFeature {
  signTransaction: (input: {
    account: WalletAccount;
    transaction: Uint8Array;
    chain: string;
  }) => Promise<Array<{ signedTransaction: Uint8Array }>>;
}

export class WalletError extends Error {
  readonly code: string;

  constructor(code: string, message?: string) {
    super(message ?? code);
    this.code = code;
  }
}

export function devnetWallets(): Wallet[] {
  return getWallets()
    .get()
    .filter((wallet) =>
      wallet.chains.includes(DEVNET_CHAIN) &&
      "standard:connect" in wallet.features &&
      "solana:signTransaction" in wallet.features);
}

export async function connect(wallet: Wallet): Promise<ConnectedWallet> {
  const feature = wallet.features["standard:connect"] as ConnectFeature | undefined;
  if (feature === undefined) throw new WalletError("WALLET_CONNECT_UNSUPPORTED");
  const { accounts } = await feature.connect();
  const account = accounts.find((candidate) => candidate.chains.includes(DEVNET_CHAIN));
  if (account === undefined) throw new WalletError("WALLET_NOT_DEVNET", "The wallet has no solana:devnet account.");
  return { walletName: wallet.name, address: account.address, account, wallet };
}

/** Signs the prepared wire transaction; the backend re-validates the result. */
export async function signTransaction(
  connected: ConnectedWallet,
  transactionBase64: string,
): Promise<string> {
  const feature = connected.wallet.features["solana:signTransaction"] as SignTransactionFeature | undefined;
  if (feature === undefined) throw new WalletError("WALLET_SIGN_UNSUPPORTED");
  const transaction = Uint8Array.from(atob(transactionBase64), (character) => character.charCodeAt(0));
  const [result] = await feature.signTransaction({
    account: connected.account,
    transaction,
    chain: DEVNET_CHAIN,
  });
  if (result?.signedTransaction === undefined) throw new WalletError("WALLET_NO_SIGNATURE");
  let binary = "";
  for (const byte of result.signedTransaction) binary += String.fromCharCode(byte);
  return btoa(binary);
}
