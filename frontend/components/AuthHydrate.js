"use client";

import { useEffect } from "react";
import { api } from "@/lib/api";
import { useWalletStore } from "@/lib/store";

export function AuthHydrate() {
  const setAuthStatus = useWalletStore((s) => s.setAuthStatus);
  const setSession = useWalletStore((s) => s.setSession);
  const disconnect = useWalletStore((s) => s.disconnect);

  useEffect(() => {
    let active = true;

    async function restoreSession() {
      const token = localStorage.getItem("jwt");
      if (!token) {
        setAuthStatus("idle");
        return;
      }

      try {
        const session = await api("/auth/session");
        if (active && session.wallet) {
          setSession({ address: session.wallet, token });
        } else if (active) {
          disconnect();
        }
      } catch {
        if (active) disconnect();
      }
    }

    function handleAccountsChanged(accounts) {
      const currentAddress = useWalletStore.getState().address;
      if (
        currentAddress &&
        (!accounts[0] ||
          accounts[0].toLowerCase() !== currentAddress.toLowerCase())
      ) {
        disconnect();
      }
    }

    window.ethereum?.on?.("accountsChanged", handleAccountsChanged);
    restoreSession();

    return () => {
      active = false;
      window.ethereum?.removeListener?.(
        "accountsChanged",
        handleAccountsChanged
      );
    };
  }, [disconnect, setAuthStatus, setSession]);

  return null;
}
