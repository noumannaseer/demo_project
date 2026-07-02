const { randomBytes } = require("crypto");
const jwt = require("jsonwebtoken");
const { SiweMessage } = require("siwe");
const { getAddress, isAddress } = require("ethers");
const {
  upsertUserNonce,
  findUserByWallet,
  findUserById,
  consumeUserNonce,
} = require("../db/repository");
const { config } = require("../config");
const { setWithExpiry, getKey, deleteKey } = require("./redis");

function authError(message, status = 401) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function normalizeWalletAddress(walletAddress) {
  if (typeof walletAddress !== "string" || !isAddress(walletAddress)) {
    throw authError("Invalid wallet address", 400);
  }
  return getAddress(walletAddress).toLowerCase();
}

async function createNonce(walletAddress) {
  const wallet = normalizeWalletAddress(walletAddress);
  const nonce = randomBytes(16).toString("hex");
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await upsertUserNonce(wallet, nonce, expires);
  return { nonce, expiresAt: expires };
}

async function verifySiwe(message, signature, walletAddress) {
  const wallet = normalizeWalletAddress(walletAddress);
  let siwe;
  try {
    siwe = new SiweMessage(message);
  } catch {
    throw authError("Invalid SIWE message", 400);
  }

  if (siwe.address.toLowerCase() !== wallet) {
    throw authError("Wallet address mismatch");
  }
  if (siwe.domain !== config.siweDomain) {
    throw authError("Invalid SIWE domain");
  }
  if (siwe.uri !== config.siweUri) {
    throw authError("Invalid SIWE URI");
  }
  if (Number(siwe.chainId) !== config.chainId) {
    throw authError("Invalid SIWE chain");
  }

  const user = await findUserByWallet(wallet);
  if (!user || !user.nonce) {
    throw authError("Invalid nonce");
  }

  const expectedNonce = user.nonce;
  const expiresAt = Date.parse(user.nonce_expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    await consumeUserNonce(wallet, expectedNonce);
    throw authError("Nonce expired");
  }

  const verification = await siwe.verify(
    {
      signature,
      domain: config.siweDomain,
      nonce: expectedNonce,
      time: new Date().toISOString(),
    },
    { suppressExceptions: true }
  );
  if (!verification.success) {
    throw authError("Invalid signature");
  }

  const consumed = await consumeUserNonce(wallet, expectedNonce);
  if (consumed.reason === "expired") {
    throw authError("Nonce expired");
  }
  if (consumed.reason) {
    throw authError("Invalid nonce");
  }

  const token = jwt.sign(
    { sub: consumed.user.id, wallet },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );

  return { token, user: { id: consumed.user.id, wallet } };
}

async function getSession(userId) {
  return findUserById(userId);
}

async function storeIdempotency(userId, campaignId, key) {
  const redisKey = `claim:${userId}:${campaignId}:${key}`;
  const existing = await getKey(redisKey);
  if (existing) return false;
  await setWithExpiry(redisKey, "1", 3600);
  return true;
}

async function invalidateSession(userId) {
  await deleteKey(`session:${userId}`);
}

module.exports = {
  createNonce,
  verifySiwe,
  getSession,
  storeIdempotency,
  invalidateSession,
};
