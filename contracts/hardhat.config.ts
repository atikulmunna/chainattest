import "@nomicfoundation/hardhat-toolbox";
import { HardhatUserConfig } from "hardhat/config";

// Optional public-testnet config. Reads a Sepolia RPC endpoint and a funded
// deployer key from the environment so the repo has no secrets committed and the
// network is simply absent when the vars are unset (local Hardhat still works):
//   SEPOLIA_RPC_URL      e.g. https://sepolia.infura.io/v3/<key> (free tier)
//   SEPOLIA_DEPLOYER_KEY 0x-prefixed private key of a faucet-funded account
const SEPOLIA_RPC_URL = process.env.SEPOLIA_RPC_URL ?? "";
const SEPOLIA_DEPLOYER_KEY = process.env.SEPOLIA_DEPLOYER_KEY ?? "";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.26",
    settings: {
      viaIR: true,
      evmVersion: "cancun",
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  networks: {
    ...(SEPOLIA_RPC_URL
      ? {
          sepolia: {
            url: SEPOLIA_RPC_URL,
            chainId: 11155111,
            accounts: SEPOLIA_DEPLOYER_KEY ? [SEPOLIA_DEPLOYER_KEY] : []
          }
        }
      : {})
  },
  paths: {
    sources: "./src",
    tests: "./test"
  }
};

export default config;
