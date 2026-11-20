// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EvidenceLedger
/// @notice Tamper-evident record of sealed farm-security events (livestock theft evidence).
/// Cameras seal each event off-chain (SHA-256 hash + device signature) and a
/// reporter wallet anchors the hash here. Images and personal data never go on-chain.
/// People who handle the evidence later (ranger, police, insurer) add custody entries,
/// giving a verifiable who-handled-what-and-when trail.
/// Compile with evmVersion "paris" so it runs on any EVM testnet.
contract EvidenceLedger {
    struct Record {
        string  deviceId;
        uint64  deviceTime;   // time reported by the camera device
        uint64  blockTime;    // time the chain accepted it
        address reporter;     // wallet that submitted it
        bytes   signature;    // device's Ed25519 signature over the event hash (64 bytes)
    }

    struct CustodyEntry {
        address handler;
        string  action;       // e.g. "reviewed by ranger", "exported for case"
        uint64  time;
    }

    address public owner;
    mapping(address => bool) public authorised;     // reporters: wallets that may anchor events
    mapping(address => bool) public handlers;       // handlers: wallets that may log custody actions
    mapping(bytes32 => Record) public records;      // eventHash => record
    mapping(bytes32 => CustodyEntry[]) private _custody;

    event EventRecorded(bytes32 indexed eventHash, string deviceId, uint64 deviceTime, address reporter);
    event CustodyLogged(bytes32 indexed eventHash, address indexed handler, string action);
    event ReporterSet(address indexed reporter, bool allowed);
    event HandlerSet(address indexed handler, bool allowed);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        authorised[msg.sender] = true;
        handlers[msg.sender] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // ── access control (owner only) ─────────────────────────────────────────

    /// Authorise or revoke a camera/gateway wallet (e.g. if a device is stolen).
    function setReporter(address reporter, bool allowed) external onlyOwner {
        authorised[reporter] = allowed;
        emit ReporterSet(reporter, allowed);
    }

    /// Authorise or revoke someone who may log custody actions.
    function setHandler(address handler, bool allowed) external onlyOwner {
        handlers[handler] = allowed;
        emit HandlerSet(handler, allowed);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ── evidence anchoring (authorised reporters) ───────────────────────────

    function recordEvent(
        bytes32 eventHash,
        string calldata deviceId,
        uint64 deviceTime,
        bytes calldata signature
    ) external {
        require(authorised[msg.sender], "reporter not authorised");
        require(bytes(deviceId).length > 0, "empty device id");
        require(signature.length == 64, "bad signature length");
        require(records[eventHash].blockTime == 0, "already recorded");
        records[eventHash] = Record(deviceId, deviceTime, uint64(block.timestamp), msg.sender, signature);
        emit EventRecorded(eventHash, deviceId, deviceTime, msg.sender);
    }

    // ── chain of custody (authorised handlers) ──────────────────────────────

    function logCustody(bytes32 eventHash, string calldata action) external {
        require(handlers[msg.sender], "handler not authorised");
        require(records[eventHash].blockTime != 0, "unknown event");
        require(bytes(action).length > 0 && bytes(action).length <= 140, "bad action length");
        _custody[eventHash].push(CustodyEntry(msg.sender, action, uint64(block.timestamp)));
        emit CustodyLogged(eventHash, msg.sender, action);
    }

    // ── reads ───────────────────────────────────────────────────────────────

    function isRecorded(bytes32 eventHash) external view returns (bool) {
        return records[eventHash].blockTime != 0;
    }

    function custodyCount(bytes32 eventHash) external view returns (uint256) {
        return _custody[eventHash].length;
    }

    function getCustody(bytes32 eventHash, uint256 index)
        external view returns (address handler, string memory action, uint64 time)
    {
        CustodyEntry storage c = _custody[eventHash][index];
        return (c.handler, c.action, c.time);
    }
}
