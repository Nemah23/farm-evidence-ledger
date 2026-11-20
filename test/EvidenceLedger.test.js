const { expect } = require("chai");
const { ethers } = require("hardhat");

// Mock data only: fake device, fake hash, 64-byte fake signature (no real people or funds).
const HASH_1 = ethers.keccak256(ethers.toUtf8Bytes("mock event 1"));
const HASH_2 = ethers.keccak256(ethers.toUtf8Bytes("mock event 2"));
const SIG = "0x" + "ab".repeat(64);
const DEVICE = "mock-farm-cam-01";
const NOW = 1_800_000_000;

describe("EvidenceLedger", function () {
  let ledger, owner, camera, ranger, stranger;

  beforeEach(async function () {
    [owner, camera, ranger, stranger] = await ethers.getSigners();
    ledger = await ethers.deployContract("EvidenceLedger");
    await ledger.waitForDeployment();
  });

  describe("deployment", function () {
    it("makes the deployer owner, reporter and handler", async function () {
      expect(await ledger.owner()).to.equal(owner.address);
      expect(await ledger.authorised(owner.address)).to.equal(true);
      expect(await ledger.handlers(owner.address)).to.equal(true);
    });
  });

  describe("recording events", function () {
    it("stores a record and emits EventRecorded", async function () {
      await expect(ledger.recordEvent(HASH_1, DEVICE, NOW, SIG))
        .to.emit(ledger, "EventRecorded")
        .withArgs(HASH_1, DEVICE, NOW, owner.address);
      const rec = await ledger.records(HASH_1);
      expect(rec.deviceId).to.equal(DEVICE);
      expect(rec.deviceTime).to.equal(NOW);
      expect(rec.blockTime).to.be.gt(0);
      expect(rec.reporter).to.equal(owner.address);
      expect(rec.signature).to.equal(SIG);
      expect(await ledger.isRecorded(HASH_1)).to.equal(true);
      expect(await ledger.isRecorded(HASH_2)).to.equal(false);
    });

    it("rejects a duplicate hash", async function () {
      await ledger.recordEvent(HASH_1, DEVICE, NOW, SIG);
      await expect(ledger.recordEvent(HASH_1, DEVICE, NOW, SIG))
        .to.be.revertedWith("already recorded");
    });

    it("rejects an empty device id", async function () {
      await expect(ledger.recordEvent(HASH_1, "", NOW, SIG))
        .to.be.revertedWith("empty device id");
    });

    it("rejects a signature that is not 64 bytes", async function () {
      await expect(ledger.recordEvent(HASH_1, DEVICE, NOW, "0x1234"))
        .to.be.revertedWith("bad signature length");
    });

    it("rejects wallets that are not authorised reporters", async function () {
      await expect(ledger.connect(stranger).recordEvent(HASH_1, DEVICE, NOW, SIG))
        .to.be.revertedWith("reporter not authorised");
    });
  });

  describe("access control", function () {
    it("lets only the owner authorise reporters", async function () {
      await expect(ledger.connect(stranger).setReporter(camera.address, true))
        .to.be.revertedWith("not owner");
      await expect(ledger.setReporter(camera.address, true))
        .to.emit(ledger, "ReporterSet").withArgs(camera.address, true);
      await expect(ledger.connect(camera).recordEvent(HASH_1, DEVICE, NOW, SIG))
        .to.emit(ledger, "EventRecorded");
    });

    it("stops a revoked reporter (e.g. a stolen camera) from writing", async function () {
      await ledger.setReporter(camera.address, true);
      await ledger.connect(camera).recordEvent(HASH_1, DEVICE, NOW, SIG);
      await ledger.setReporter(camera.address, false);
      await expect(ledger.connect(camera).recordEvent(HASH_2, DEVICE, NOW, SIG))
        .to.be.revertedWith("reporter not authorised");
      // evidence recorded before the revocation stays intact
      expect(await ledger.isRecorded(HASH_1)).to.equal(true);
    });

    it("lets only the owner authorise handlers", async function () {
      await expect(ledger.connect(stranger).setHandler(ranger.address, true))
        .to.be.revertedWith("not owner");
      await expect(ledger.setHandler(ranger.address, true))
        .to.emit(ledger, "HandlerSet").withArgs(ranger.address, true);
    });

    it("transfers ownership and blocks the old owner", async function () {
      await expect(ledger.transferOwnership(ethers.ZeroAddress))
        .to.be.revertedWith("zero address");
      await expect(ledger.transferOwnership(ranger.address))
        .to.emit(ledger, "OwnershipTransferred").withArgs(owner.address, ranger.address);
      expect(await ledger.owner()).to.equal(ranger.address);
      await expect(ledger.setReporter(camera.address, true)).to.be.revertedWith("not owner");
    });
  });

  describe("chain of custody", function () {
    beforeEach(async function () {
      await ledger.recordEvent(HASH_1, DEVICE, NOW, SIG);
      await ledger.setHandler(ranger.address, true);
    });

    it("lets an authorised handler log actions in order", async function () {
      await expect(ledger.connect(ranger).logCustody(HASH_1, "reviewed by ranger"))
        .to.emit(ledger, "CustodyLogged").withArgs(HASH_1, ranger.address, "reviewed by ranger");
      await ledger.logCustody(HASH_1, "exported for case");
      expect(await ledger.custodyCount(HASH_1)).to.equal(2);
      const first = await ledger.getCustody(HASH_1, 0);
      expect(first.handler).to.equal(ranger.address);
      expect(first.action).to.equal("reviewed by ranger");
      const second = await ledger.getCustody(HASH_1, 1);
      expect(second.handler).to.equal(owner.address);
      expect(second.action).to.equal("exported for case");
    });

    it("rejects handlers that are not authorised", async function () {
      await expect(ledger.connect(stranger).logCustody(HASH_1, "tampering attempt"))
        .to.be.revertedWith("handler not authorised");
    });

    it("rejects custody entries for events that were never recorded", async function () {
      await expect(ledger.logCustody(HASH_2, "reviewed"))
        .to.be.revertedWith("unknown event");
    });

    it("rejects empty or over-long action text", async function () {
      await expect(ledger.logCustody(HASH_1, "")).to.be.revertedWith("bad action length");
      await expect(ledger.logCustody(HASH_1, "x".repeat(141)))
        .to.be.revertedWith("bad action length");
    });
  });
});
