require("@nomicfoundation/hardhat-ethers");
require("@nomicfoundation/hardhat-chai-matchers");

// Throwaway test-wallet key: put it in a .env file (copy .env.example) or an environment
// variable. Never write it in this file and never commit it. With or without 0x both work.
try { require("dotenv").config(); } catch (e) { /* dotenv optional */ }
const RAW_KEY = process.env.PRIVATE_KEY;
const PRIVATE_KEY = RAW_KEY ? (RAW_KEY.startsWith("0x") ? RAW_KEY : "0x" + RAW_KEY) : undefined;

module.exports = {
  solidity: {
    version: "0.8.26",
    settings: { evmVersion: "paris", optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    fuji: {
      url: process.env.FUJI_RPC_URL || "https://api.avax-test.network/ext/bc/C/rpc",
      chainId: 43113,
      accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
    },
  },
};
