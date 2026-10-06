// Mock Wallet Standard wallet injected into the page before any script runs.
//
// It implements `standard:connect` and `solana:signTransaction` on the
// `solana:devnet` chain and returns a deterministic signed payload. The panel
// never sees a key: the mock holds none either, which is exactly the property
// under test.
export const MOCK_WALLET_ADDRESS = "9zjRUZLLE4nRvXtDkYPJDGnnLrLrGCUbHVLbdaFmMbJq";

export function mockWalletScript(options: { rejectSigning?: boolean } = {}): string {
  return `(() => {
  const address = ${JSON.stringify(MOCK_WALLET_ADDRESS)};
  const reject = ${options.rejectSigning === true};
  const account = {
    address,
    publicKey: new Uint8Array(32),
    chains: ["solana:devnet"],
    features: ["solana:signTransaction"],
    label: "Mock devnet operator",
  };
  const wallet = {
    version: "1.0.0",
    name: "OneLayer Mock Wallet",
    icon: "data:image/svg+xml;base64,PHN2Zy8+",
    chains: ["solana:devnet"],
    accounts: [account],
    features: {
      "standard:connect": {
        version: "1.0.0",
        connect: async () => ({ accounts: [account] }),
      },
      "standard:events": {
        version: "1.0.0",
        on: () => () => {},
      },
      "solana:signTransaction": {
        version: "1.0.0",
        supportedTransactionVersions: ["legacy", 0],
        signTransaction: async ({ transaction }) => {
          if (reject) throw new Error("User rejected the request");
          const signed = new Uint8Array(transaction.length + 8);
          signed.set(transaction, 0);
          signed.set([1, 2, 3, 4, 5, 6, 7, 8], transaction.length);
          return [{ signedTransaction: signed }];
        },
      },
    },
  };
  // Wallet Standard registration: answer the app's ready event and announce
  // ourselves for apps that were already listening.
  window.addEventListener("wallet-standard:app-ready", (event) => {
    event.detail.register(wallet);
  });
  window.dispatchEvent(new CustomEvent("wallet-standard:register-wallet", {
    detail: (api) => api.register(wallet),
  }));
  window.__onelayerMockWallet = wallet;
})();`;
}
