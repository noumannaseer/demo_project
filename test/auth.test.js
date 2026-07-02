const assert = require("node:assert/strict");
const { after, before, test } = require("node:test");
const fs = require("node:fs/promises");
const path = require("node:path");
const { Wallet } = require("ethers");
const { SiweMessage } = require("siwe");

const dataFile = path.join(__dirname, `.auth-data-${process.pid}.json`);
process.env.DATA_FILE = dataFile;
process.env.JWT_SECRET = "test-only-secret";
process.env.JWT_EXPIRES_IN = "5m";
process.env.CORS_ORIGIN = "http://localhost:3000";
process.env.SIWE_DOMAIN = "localhost:3000";
process.env.SIWE_URI = "http://localhost:3000";
process.env.CHAIN_ID = "31337";

const { createApp } = require("../src/app");
const {
  createNonce,
  getSession,
  verifySiwe,
} = require("../src/services/authService");
const { loadDb, saveDb } = require("../src/db/store");

let server;
let baseUrl;

function buildMessage(walletAddress, nonce, overrides = {}) {
  return new SiweMessage({
    domain: "localhost:3000",
    address: walletAddress,
    statement: "Sign in to NFT Airdrop Platform",
    uri: "http://localhost:3000",
    version: "1",
    chainId: 31337,
    nonce,
    expirationTime: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    ...overrides,
  }).prepareMessage();
}

before(async () => {
  server = createApp().listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  await fs.rm(dataFile, { force: true });
});

test("rejects an invalid wallet address", async () => {
  await assert.rejects(
    () => createNonce("not-a-wallet"),
    /Invalid wallet address/
  );
});

test("authenticates a valid SIWE request and prevents replay", async () => {
  const wallet = Wallet.createRandom();
  const { nonce } = await createNonce(wallet.address);
  const message = buildMessage(wallet.address, nonce);
  const signature = await wallet.signMessage(message);

  const result = await verifySiwe(
    message,
    signature,
    wallet.address
  );
  assert.ok(result.token);
  assert.equal(result.user.wallet, wallet.address.toLowerCase());

  const session = await getSession(result.user.id);
  assert.equal(session.wallet_address, wallet.address.toLowerCase());

  await assert.rejects(
    () => verifySiwe(message, signature, wallet.address),
    /Invalid nonce/
  );
});

test("rejects a wallet address that differs from the signed message", async () => {
  const wallet = Wallet.createRandom();
  const otherWallet = Wallet.createRandom();
  const { nonce } = await createNonce(wallet.address);
  const message = buildMessage(wallet.address, nonce);
  const signature = await wallet.signMessage(message);

  await assert.rejects(
    () => verifySiwe(message, signature, otherWallet.address),
    /Wallet address mismatch/
  );
});

test("rejects the wrong domain and chain", async () => {
  const wallet = Wallet.createRandom();
  const first = await createNonce(wallet.address);
  const wrongDomain = buildMessage(wallet.address, first.nonce, {
    domain: "evil.example",
    uri: "https://evil.example",
  });
  const wrongDomainSignature = await wallet.signMessage(wrongDomain);
  await assert.rejects(
    () =>
      verifySiwe(
        wrongDomain,
        wrongDomainSignature,
        wallet.address
      ),
    /Invalid SIWE domain/
  );

  const second = await createNonce(wallet.address);
  const wrongChain = buildMessage(wallet.address, second.nonce, {
    chainId: 1,
  });
  const wrongChainSignature = await wallet.signMessage(wrongChain);
  await assert.rejects(
    () =>
      verifySiwe(
        wrongChain,
        wrongChainSignature,
        wallet.address
      ),
    /Invalid SIWE chain/
  );
});

test("rejects an expired server nonce", async () => {
  const wallet = Wallet.createRandom();
  const { nonce } = await createNonce(wallet.address);
  const db = await loadDb();
  const user = db.users.find(
    (entry) => entry.wallet_address === wallet.address.toLowerCase()
  );
  user.nonce_expires_at = new Date(Date.now() - 1000).toISOString();
  await saveDb();

  const message = buildMessage(wallet.address, nonce);
  const signature = await wallet.signMessage(message);
  await assert.rejects(
    () =>
      verifySiwe(
        message,
        signature,
        wallet.address
      ),
    /Nonce expired/
  );
});

test("serves the full nonce, verify and session API flow", async () => {
  const wallet = Wallet.createRandom();
  const nonceResponse = await fetch(`${baseUrl}/auth/nonce`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ walletAddress: wallet.address }),
  });
  assert.equal(nonceResponse.status, 200);
  const { nonce } = await nonceResponse.json();

  const message = buildMessage(wallet.address, nonce);
  const signature = await wallet.signMessage(message);
  const verifyResponse = await fetch(`${baseUrl}/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      walletAddress: wallet.address,
      message,
      signature,
    }),
  });
  assert.equal(verifyResponse.status, 200);
  const { token } = await verifyResponse.json();

  const sessionResponse = await fetch(`${baseUrl}/auth/session`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(sessionResponse.status, 200);
  const session = await sessionResponse.json();
  assert.equal(session.wallet, wallet.address.toLowerCase());

  const invalidSession = await fetch(`${baseUrl}/auth/session`, {
    headers: { Authorization: "Bearer invalid" },
  });
  assert.equal(invalidSession.status, 401);
});
