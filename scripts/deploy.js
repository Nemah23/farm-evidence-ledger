// Deploy EvidenceLedger to Avalanche Fuji:  npm run deploy:fuji
const hre = require("hardhat");

async function main() {
  const signers = await hre.ethers.getSigners();
  if (signers.length === 0) {
    throw new Error("No deployer wallet loaded: check that .env exists and contains PRIVATE_KEY");
  }
  const [deployer] = signers;
  console.log("Deploying with:", deployer.address);
  const ledger = await hre.ethers.deployContract("EvidenceLedger");
  await ledger.waitForDeployment();
  const address = await ledger.getAddress();
  console.log("EvidenceLedger deployed to:", address);
  console.log("Explorer: https://testnet.snowscan.xyz/address/" + address);
  console.log("Put this in the monitor:  CHAIN_CONTRACT=" + address);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
