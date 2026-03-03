#!/usr/bin/env python3
"""
DandG — CLI and helpers for the DoppelBanger twin-entry attestation ledger.
Register twin pairs, strike mirrors, resolve pairs, post/claim bounties, manage stripes.
Usage:
  python DandG_app.py config
  python DandG_app.py hash --left "payload" --right "payload"
  python DandG_app.py pair-id --left-hash 0x... --right-hash 0x... [--binder 0x...] [--salt 0]
  python DandG_app.py register --rpc-url URL --private-key KEY --contract 0x... --pair-id 0x... --left-hash 0x... --right-hash 0x...
  python DandG_app.py strike --rpc-url URL --private-key KEY --contract 0x... --pair-id 0x... --side 0|1 [--reason 0x...]
  python DandG_app.py resolve --rpc-url URL --private-key KEY --contract 0x... --pair-id 0x... --outcome 0|1|2|3
  python DandG_app.py post-bounty --rpc-url URL --private-key KEY --contract 0x... --pair-id 0x... --value-wei VALUE
  python DandG_app.py claim-bounty --rpc-url URL --private-key KEY --contract 0x... --pair-id 0x...
  python DandG_app.py add-stripe --rpc-url URL --private-key KEY --contract 0x... --stripe-id 0x... --anchor-hash 0x...
  python DandG_app.py link-stripe --rpc-url URL --private-key KEY --contract 0x... --stripe-id 0x... --pair-id 0x...
  python DandG_app.py get-pair --rpc-url URL --contract 0x... --pair-id 0x...
  python DandG_app.py get-stripe --rpc-url URL --contract 0x... --stripe-id 0x...
  python DandG_app.py list-pairs --rpc-url URL --contract 0x... [--from-idx N] [--to-idx M]
  python DandG_app.py list-stripes --rpc-url URL --contract 0x... [--from-idx N] [--to-idx M]
  python DandG_app.py stats --rpc-url URL --contract 0x...
  python DandG_app.py constants | reference | version | demo | interactive
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import secrets
import sys
from pathlib import Path
from typing import Any, Optional

APP_NAME = "DandG"
DANDG_VERSION = "1.0.0"
CONTRACT_NAME = "DoppelBanger"

# Default RPC and contract (user can override via env or args)
DEFAULT_RPC_URL = os.environ.get("DANDG_RPC_URL", "http://127.0.0.1:8545")
DEFAULT_CONTRACT_ADDRESS = os.environ.get("DANDG_CONTRACT", "")

# Outcome constants (match DoppelBanger.sol)
OUTCOME_NONE = 0
OUTCOME_LEFT = 1
OUTCOME_RIGHT = 2
OUTCOME_TIE = 3
OUTCOME_LABELS = {OUTCOME_NONE: "none", OUTCOME_LEFT: "left", OUTCOME_RIGHT: "right", OUTCOME_TIE: "tie"}

# Minimal ABI for DoppelBanger view and state-changing functions we use
DOPPEL_BANGER_ABI = [
    {"inputs": [{"internalType": "bytes32", "name": "pairId", "type": "bytes32"}, {"internalType": "bytes32", "name": "leftHash", "type": "bytes32"}, {"internalType": "bytes32", "name": "rightHash", "type": "bytes32"}], "name": "registerTwin", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "pairId", "type": "bytes32"}, {"internalType": "uint8", "name": "side", "type": "uint8"}, {"internalType": "bytes32", "name": "reasonHash", "type": "bytes32"}], "name": "strikeMirror", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "pairId", "type": "bytes32"}, {"internalType": "uint8", "name": "outcome", "type": "uint8"}], "name": "resolvePair", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "pairId", "type": "bytes32"}], "name": "postBounty", "outputs": [], "stateMutability": "payable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "pairId", "type": "bytes32"}], "name": "claimBounty", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "stripeId", "type": "bytes32"}, {"internalType": "bytes32", "name": "anchorHash", "type": "bytes32"}], "name": "addStripe", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "stripeId", "type": "bytes32"}, {"internalType": "bytes32", "name": "pairId", "type": "bytes32"}], "name": "linkStripeToPair", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "pairId", "type": "bytes32"}], "name": "getPair", "outputs": [{"internalType": "bytes32", "name": "leftHash", "type": "bytes32"}, {"internalType": "bytes32", "name": "rightHash", "type": "bytes32"}, {"internalType": "address", "name": "binder", "type": "address"}, {"internalType": "uint256", "name": "registeredAtBlock", "type": "uint256"}, {"internalType": "uint8", "name": "resolutionOutcome", "type": "uint8"}, {"internalType": "bool", "name": "resolved", "type": "bool"}, {"internalType": "uint256", "name": "strikeCountLeft", "type": "uint256"}, {"internalType": "uint256", "name": "strikeCountRight", "type": "uint256"}, {"internalType": "uint256", "name": "bountyWei", "type": "uint256"}, {"internalType": "bool", "name": "bountyClaimed", "type": "bool"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "stripeId", "type": "bytes32"}], "name": "getStripe", "outputs": [{"internalType": "bytes32", "name": "anchorHash", "type": "bytes32"}, {"internalType": "address", "name": "owner", "type": "address"}, {"internalType": "uint256", "name": "createdAtBlock", "type": "uint256"}, {"internalType": "bytes32", "name": "linkedPairId", "type": "bytes32"}, {"internalType": "bool", "name": "linked", "type": "bool"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getGlobalStats", "outputs": [{"internalType": "uint256", "name": "totalPairs", "type": "uint256"}, {"internalType": "uint256", "name": "totalStripes", "type": "uint256"}, {"internalType": "uint256", "name": "deployBlockNum", "type": "uint256"}, {"internalType": "uint256", "name": "currentFeeBps", "type": "uint256"}, {"internalType": "uint256", "name": "currentMaxPairsPerBinder", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "fromIndex", "type": "uint256"}, {"internalType": "uint256", "name": "toIndex", "type": "uint256"}], "name": "getPairsInRange", "outputs": [{"internalType": "bytes32[]", "name": "pairIds", "type": "bytes32[]"}, {"internalType": "bytes32[]", "name": "leftHashes", "type": "bytes32[]"}, {"internalType": "bytes32[]", "name": "rightHashes", "type": "bytes32[]"}, {"internalType": "address[]", "name": "binders", "type": "address[]"}, {"internalType": "bool[]", "name": "resolvedFlags", "type": "bool[]"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "fromIndex", "type": "uint256"}, {"internalType": "uint256", "name": "toIndex", "type": "uint256"}], "name": "getStripesInRange", "outputs": [{"internalType": "bytes32[]", "name": "stripeIds", "type": "bytes32[]"}, {"internalType": "bytes32[]", "name": "anchorHashes", "type": "bytes32[]"}, {"internalType": "address[]", "name": "owners", "type": "address[]"}, {"internalType": "bool[]", "name": "linkedFlags", "type": "bool[]"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "bytes", "name": "leftPayload", "type": "bytes"}, {"internalType": "bytes", "name": "rightPayload", "type": "bytes"}], "name": "hashTwinPayload", "outputs": [{"internalType": "bytes32", "name": "leftHash", "type": "bytes32"}, {"internalType": "bytes32", "name": "rightHash", "type": "bytes32"}], "stateMutability": "pure", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "leftHash", "type": "bytes32"}, {"internalType": "bytes32", "name": "rightHash", "type": "bytes32"}, {"internalType": "address", "name": "binder", "type": "address"}, {"internalType": "uint256", "name": "salt", "type": "uint256"}], "name": "derivePairId", "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}], "stateMutability": "pure", "type": "function"},
    {"inputs": [], "name": "pairCount", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "stripeCount", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}], "name": "getPairIdAt", "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}], "name": "getStripeIdAt", "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "pairId", "type": "bytes32"}], "name": "pairExists", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "stripeId", "type": "bytes32"}], "name": "stripeExists", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "contractBalanceWei", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
]

# -----------------------------------------------------------------------------
# KECCAK (if no web3, fallback to pycryptodome or pure)
# -----------------------------------------------------------------------------

def _keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak
        h = keccak.new(digest_bits=256)
        h.update(data)
        return h.digest()
    except ImportError:
        try:
            from eth_hash.auto import keccak as eth_keccak
            return eth_keccak(data)
        except ImportError:
            return hashlib.sha3_256(data).digest()

def bytes32_from_hex(s: str) -> bytes:
    s = s.strip()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 64:
        raise ValueError("Expected 64 hex chars (32 bytes)")
    return bytes.fromhex(s)

def hex_from_bytes32(b: bytes) -> str:
    return "0x" + b.hex()

def hash_payload(payload: bytes) -> str:
    return "0x" + _keccak256(payload).hex()

def hash_string(s: str) -> str:
    return hash_payload(s.encode("utf-8"))

def derive_pair_id_local(left_hash_hex: str, right_hash_hex: str, binder: str, salt: int) -> str:
    left_b = bytes32_from_hex(left_hash_hex)
    right_b = bytes32_from_hex(right_hash_hex)
    binder_b = bytes.fromhex(binder.replace("0x", "").lower().zfill(40))
    data = left_b + right_b + binder_b + salt.to_bytes(32, "big")
    return "0x" + _keccak256(data).hex()

# -----------------------------------------------------------------------------
# WEB3 HELPERS
# -----------------------------------------------------------------------------

def get_w3(rpc_url: str):
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not w3.is_connected():
            raise RuntimeError("Not connected to RPC")
        return w3
    except ImportError:
        raise RuntimeError("Install web3: pip install web3")

def get_contract(w3, address: str):
    from web3 import Web3
    return w3.eth.contract(address=Web3.to_checksum_address(address), abi=DOPPEL_BANGER_ABI)

def get_signer_account(w3, private_key: str):
    from web3 import Web3
    pk = private_key.strip()
    if pk.startswith("0x"):
        pk = pk[2:]
    return w3.eth.account.from_key(pk)

# -----------------------------------------------------------------------------
# COMMANDS: HASH / PAIR-ID (no RPC)
# -----------------------------------------------------------------------------

def cmd_hash(args: argparse.Namespace) -> int:
    left = (args.left or "").encode("utf-8")
    right = (args.right or "").encode("utf-8")
    left_h = hash_payload(left)
    right_h = hash_payload(right)
    print("leftHash:", left_h)
    print("rightHash:", right_h)
    if getattr(args, "json_out", False):
        print(json.dumps({"leftHash": left_h, "rightHash": right_h}))
    return 0

def cmd_pair_id(args: argparse.Namespace) -> int:
    left_hex = args.left_hash or "0x" + "00" * 32
    right_hex = args.right_hash or "0x" + "00" * 32
    binder = args.binder or "0x" + "00" * 20
    salt = getattr(args, "salt", 0) or 0
    try:
        pid = derive_pair_id_local(left_hex, right_hex, binder, salt)
        print("pairId:", pid)
        if getattr(args, "json_out", False):
            print(json.dumps({"pairId": pid}))
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

# -----------------------------------------------------------------------------
# COMMANDS: REGISTER / STRIKE / RESOLVE / BOUNTY / STRIPE (need RPC + key)
# -----------------------------------------------------------------------------

def cmd_register(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    pk = getattr(args, "private_key", None)
    if not pk:
        print("Error: --private-key required", file=sys.stderr)
        return 1
    pair_id = args.pair_id
    left_hash = args.left_hash
    right_hash = args.right_hash
    if not all([pair_id, left_hash, right_hash]):
        print("Error: --pair-id, --left-hash, --right-hash required", file=sys.stderr)
        return 1
    w3 = get_w3(rpc)
    acct = get_signer_account(w3, pk)
    contract = get_contract(w3, contract_addr)
    pair_id_b = bytes32_from_hex(pair_id)
    left_b = bytes32_from_hex(left_hash)
    right_b = bytes32_from_hex(right_hash)
    try:
        tx = contract.functions.registerTwin(pair_id_b, left_b, right_b).build_transaction({
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address),
        })
        signed = w3.eth.account.sign_transaction(tx, acct.key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print("Tx hash:", tx_hash.hex())
        if getattr(args, "wait", False):
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            print("Status:", "ok" if receipt["status"] == 1 else "failed")
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

def cmd_strike(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    pk = getattr(args, "private_key", None)
    if not pk:
        print("Error: --private-key required", file=sys.stderr)
        return 1
    pair_id = args.pair_id
    side = int(getattr(args, "side", 0))
    reason = getattr(args, "reason", None) or "0x" + "00" * 32
    w3 = get_w3(rpc)
    acct = get_signer_account(w3, pk)
    contract = get_contract(w3, contract_addr)
    pair_id_b = bytes32_from_hex(pair_id)
    reason_b = bytes32_from_hex(reason) if len(reason) >= 64 else bytes(32)
    try:
        tx = contract.functions.strikeMirror(pair_id_b, side, reason_b).build_transaction({
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address),
        })
        signed = w3.eth.account.sign_transaction(tx, acct.key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print("Tx hash:", tx_hash.hex())
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

def cmd_resolve(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    pk = getattr(args, "private_key", None)
    if not pk:
        print("Error: --private-key required", file=sys.stderr)
        return 1
    pair_id_b = bytes32_from_hex(args.pair_id)
    outcome = int(args.outcome)
    w3 = get_w3(rpc)
    acct = get_signer_account(w3, pk)
    contract = get_contract(w3, contract_addr)
    try:
        tx = contract.functions.resolvePair(pair_id_b, outcome).build_transaction({
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address),
        })
        signed = w3.eth.account.sign_transaction(tx, acct.key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print("Tx hash:", tx_hash.hex())
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

def cmd_post_bounty(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    pk = getattr(args, "private_key", None)
    if not pk:
        print("Error: --private-key required", file=sys.stderr)
        return 1
    value_wei = int(args.value_wei)
    pair_id_b = bytes32_from_hex(args.pair_id)
    w3 = get_w3(rpc)
    acct = get_signer_account(w3, pk)
    contract = get_contract(w3, contract_addr)
    try:
        tx = contract.functions.postBounty(pair_id_b).build_transaction({
            "from": acct.address,
            "value": value_wei,
            "nonce": w3.eth.get_transaction_count(acct.address),
        })
        signed = w3.eth.account.sign_transaction(tx, acct.key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print("Tx hash:", tx_hash.hex())
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

def cmd_claim_bounty(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    pk = getattr(args, "private_key", None)
    if not pk:
        print("Error: --private-key required", file=sys.stderr)
        return 1
    pair_id_b = bytes32_from_hex(args.pair_id)
    w3 = get_w3(rpc)
    acct = get_signer_account(w3, pk)
    contract = get_contract(w3, contract_addr)
    try:
        tx = contract.functions.claimBounty(pair_id_b).build_transaction({
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address),
        })
        signed = w3.eth.account.sign_transaction(tx, acct.key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print("Tx hash:", tx_hash.hex())
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

def cmd_add_stripe(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    pk = getattr(args, "private_key", None)
    if not pk:
        print("Error: --private-key required", file=sys.stderr)
        return 1
    stripe_id_b = bytes32_from_hex(args.stripe_id)
    anchor_b = bytes32_from_hex(args.anchor_hash)
    w3 = get_w3(rpc)
    acct = get_signer_account(w3, pk)
    contract = get_contract(w3, contract_addr)
    try:
        tx = contract.functions.addStripe(stripe_id_b, anchor_b).build_transaction({
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address),
        })
        signed = w3.eth.account.sign_transaction(tx, acct.key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print("Tx hash:", tx_hash.hex())
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

def cmd_link_stripe(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    pk = getattr(args, "private_key", None)
    if not pk:
        print("Error: --private-key required", file=sys.stderr)
        return 1
    stripe_id_b = bytes32_from_hex(args.stripe_id)
    pair_id_b = bytes32_from_hex(args.pair_id)
    w3 = get_w3(rpc)
    acct = get_signer_account(w3, pk)
    contract = get_contract(w3, contract_addr)
    try:
        tx = contract.functions.linkStripeToPair(stripe_id_b, pair_id_b).build_transaction({
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address),
        })
        signed = w3.eth.account.sign_transaction(tx, acct.key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print("Tx hash:", tx_hash.hex())
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

# -----------------------------------------------------------------------------
# COMMANDS: VIEW (RPC + contract, no key)
# -----------------------------------------------------------------------------

def cmd_get_pair(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    w3 = get_w3(rpc)
    contract = get_contract(w3, contract_addr)
    pair_id_b = bytes32_from_hex(args.pair_id)
    try:
        out = contract.functions.getPair(pair_id_b).call()
        leftHash, rightHash, binder, registeredAtBlock, resolutionOutcome, resolved, strikeCountLeft, strikeCountRight, bountyWei, bountyClaimed = out
        print("leftHash:", hex_from_bytes32(leftHash))
        print("rightHash:", hex_from_bytes32(rightHash))
        print("binder:", binder)
        print("registeredAtBlock:", registeredAtBlock)
        print("resolutionOutcome:", resolutionOutcome, OUTCOME_LABELS.get(resolutionOutcome, "?"))
        print("resolved:", resolved)
        print("strikeCountLeft:", strikeCountLeft)
        print("strikeCountRight:", strikeCountRight)
        print("bountyWei:", bountyWei)
        print("bountyClaimed:", bountyClaimed)
        if getattr(args, "json_out", False):
            print(json.dumps({
                "leftHash": hex_from_bytes32(leftHash),
                "rightHash": hex_from_bytes32(rightHash),
                "binder": binder,
                "registeredAtBlock": registeredAtBlock,
                "resolutionOutcome": resolutionOutcome,
                "resolved": resolved,
                "strikeCountLeft": strikeCountLeft,
                "strikeCountRight": strikeCountRight,
                "bountyWei": bountyWei,
                "bountyClaimed": bountyClaimed,
            }))
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0
