import { create } from "zustand";

export const useWalletStore = create((set) => ({
  address: null,
  chainId: null,
  token: null,
  authStatus: "checking",
  setAuthStatus: (authStatus) => set({ authStatus }),
  setSession: ({ address, chainId = null, token }) =>
    set({
      address,
      chainId,
      token,
      authStatus: "authenticated",
    }),
  disconnect: () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("jwt");
    }
    set({
      address: null,
      chainId: null,
      token: null,
      authStatus: "idle",
    });
  },
}));
