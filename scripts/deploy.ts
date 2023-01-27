import { ethers } from "hardhat";

const globalConfig = require("../config.json");

async function main() {
  console.log("Start deploy");
  const MevProtocol = await ethers.getContractFactory("MevProtocol");
  const mevProtocol = await MevProtocol.deploy(globalConfig.tokens);

  await mevProtocol.deployed();
  console.log("Mev Protocole deployed to:", mevProtocol.address);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
