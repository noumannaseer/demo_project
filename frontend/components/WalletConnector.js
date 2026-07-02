"use client";

import { useCallback, useState } from "react";
import { BrowserProvider } from "ethers";
import { SiweMessage } from "siwe";
import { api } from "@/lib/api";
import { useWalletStore } from "@/lib/store";

const CHAIN_ID = Number(process.env.NEXT_PUBLIC_CHAIN_ID || 31337);

export function WalletConnector() {
  const { address, token, authStatus, setSession, disconnect } =
    useWalletStore();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const connect = useCallback(async () => {
    if (!window.ethereum) {
      setError("Install MetaMask or another Web3 wallet.");
      return;
    }
    setError("");
    setIsLoading(true);

    try {
      const provider = new BrowserProvider(window.ethereum);
      await provider.send("eth_requestAccounts", []);
      const network = await provider.getNetwork();
      const chainId = Number(network.chainId);
      if (chainId !== CHAIN_ID) {
        throw new Error(`Switch your wallet to chain ${CHAIN_ID}.`);
      }

      const signer = await provider.getSigner();
      const walletAddress = await signer.getAddress();
      const { nonce, expiresAt } = await api("/auth/nonce", {
        method: "POST",
        body: JSON.stringify({ walletAddress }),
      });

      const message = new SiweMessage({
        domain: window.location.host,
        address: walletAddress,
        statement: "Sign in to NFT Airdrop Platform",
        uri: window.location.origin,
        version: "1",
        chainId,
        nonce,
        expirationTime: expiresAt,
      });

      const prepared = message.prepareMessage();
      const signature = await signer.signMessage(prepared);
      const result = await api("/auth/verify", {
        method: "POST",
        body: JSON.stringify({
          walletAddress,
          message: prepared,
          signature,
        }),
      });

      localStorage.setItem("jwt", result.token);
      setSession({
        address: result.user.wallet,
        chainId,
        token: result.token,
      });
    } catch (connectError) {
      disconnect();
      setError(
        connectError?.code === 4001
          ? "Signature request was cancelled."
          : connectError?.shortMessage ||
              connectError?.message ||
              "Wallet sign-in failed."
      );
    } finally {
      setIsLoading(false);
    }
  }, [disconnect, setSession]);

  const signOut = useCallback(async () => {
    setIsLoading(true);
    setError("");
    try {
      if (token) {
        await api("/auth/logout", { method: "POST" });
      }
    } catch {
      // Local cleanup must still happen if the API is unavailable.
    } finally {
      disconnect();
      setIsLoading(false);
    }
  }, [disconnect, token]);

  if (address && token) {
    return (
      <div className="flex items-center gap-3 group">
        <div className="rounded-full bg-gradient-to-r from-brand-500/10 to-blue-500/10 px-3 py-1 border border-brand-500/30 group-hover:border-brand-500/60 transition-all">
          <span className="text-xs text-brand-200 font-medium">
            {address.slice(0, 6)}…{address.slice(-4)}
          </span>
        </div>
        <button
          type="button"
          className="btn-ghost text-sm"
          onClick={signOut}
          disabled={isLoading}
        >
          {isLoading ? "Disconnecting…" : "Disconnect"}
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <button
        type="button"
        className="btn-primary text-sm group relative overflow-hidden"
        onClick={connect}
        disabled={isLoading || authStatus === "checking"}
      >
        <div className="absolute inset-0 bg-gradient-to-r from-brand-500 via-blue-400 to-brand-500 opacity-0 group-hover:opacity-100 transition-opacity duration-300 animate-slide-in" />
        <span className="relative z-10 flex items-center gap-2">
          <span className="inline-block w-2 h-2 bg-white rounded-full group-hover:animate-pulse" />
          {authStatus === "checking"
            ? "Checking session…"
            : isLoading
              ? "Waiting for wallet…"
              : "Connect Wallet"}
        </span>
      </button>
      {error ? (
        <p
          role="alert"
          className="max-w-64 text-right text-xs text-red-300"
        >
          {error}
        </p>
      ) : null}
    </div>
  );
}
