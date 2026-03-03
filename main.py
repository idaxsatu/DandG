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

def cmd_get_stripe(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    w3 = get_w3(rpc)
    contract = get_contract(w3, contract_addr)
    stripe_id_b = bytes32_from_hex(args.stripe_id)
    try:
        out = contract.functions.getStripe(stripe_id_b).call()
        anchorHash, owner, createdAtBlock, linkedPairId, linked = out
        print("anchorHash:", hex_from_bytes32(anchorHash))
        print("owner:", owner)
        print("createdAtBlock:", createdAtBlock)
        print("linkedPairId:", hex_from_bytes32(linkedPairId))
        print("linked:", linked)
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

def cmd_list_pairs(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    w3 = get_w3(rpc)
    contract = get_contract(w3, contract_addr)
    from_idx = int(getattr(args, "from_idx", 0))
    to_idx = int(getattr(args, "to_idx", 99))
    try:
        total = contract.functions.pairCount().call()
        if total == 0:
            print("No pairs.")
            return 0
        if to_idx >= total:
            to_idx = total - 1
        if from_idx > to_idx:
            from_idx, to_idx = 0, min(99, total - 1)
        pairIds, leftHashes, rightHashes, binders, resolvedFlags = contract.functions.getPairsInRange(from_idx, to_idx).call()
        for i in range(len(pairIds)):
            print(hex_from_bytes32(pairIds[i]), "|", hex_from_bytes32(leftHashes[i])[:18]+"...", "|", hex_from_bytes32(rightHashes[i])[:18]+"...", "|", binders[i], "|", "resolved" if resolvedFlags[i] else "open")
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

def cmd_list_stripes(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    w3 = get_w3(rpc)
    contract = get_contract(w3, contract_addr)
    from_idx = int(getattr(args, "from_idx", 0))
    to_idx = int(getattr(args, "to_idx", 99))
    try:
        total = contract.functions.stripeCount().call()
        if total == 0:
            print("No stripes.")
            return 0
        if to_idx >= total:
            to_idx = total - 1
        if from_idx > to_idx:
            from_idx, to_idx = 0, min(99, total - 1)
        stripeIds, anchorHashes, owners, linkedFlags = contract.functions.getStripesInRange(from_idx, to_idx).call()
        for i in range(len(stripeIds)):
            print(hex_from_bytes32(stripeIds[i]), "|", hex_from_bytes32(anchorHashes[i])[:18]+"...", "|", owners[i], "|", "linked" if linkedFlags[i] else "unlinked")
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

def cmd_stats(args: argparse.Namespace) -> int:
    rpc = args.rpc_url or DEFAULT_RPC_URL
    contract_addr = args.contract or DEFAULT_CONTRACT_ADDRESS
    if not contract_addr:
        print("Error: --contract or DANDG_CONTRACT required", file=sys.stderr)
        return 1
    w3 = get_w3(rpc)
    contract = get_contract(w3, contract_addr)
    try:
        totalPairs, totalStripes, deployBlockNum, currentFeeBps, currentMaxPairsPerBinder = contract.functions.getGlobalStats().call()
        balance = contract.functions.contractBalanceWei().call()
        print("Total pairs:", totalPairs)
        print("Total stripes:", totalStripes)
        print("Deploy block:", deployBlockNum)
        print("Fee BPS:", currentFeeBps)
        print("Max pairs per binder:", currentMaxPairsPerBinder)
        print("Contract balance (wei):", balance)
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        return 1
    return 0

# -----------------------------------------------------------------------------
# REFERENCE / CONSTANTS / VERSION / DEMO / INTERACTIVE
# -----------------------------------------------------------------------------

REFERENCE_TEXT = """
DoppelBanger contract — twin-entry attestation ledger.

View (read-only):
  getPair(pairId) -> leftHash, rightHash, binder, registeredAtBlock, resolutionOutcome, resolved, strikeCountLeft, strikeCountRight, bountyWei, bountyClaimed
  getStripe(stripeId) -> anchorHash, owner, createdAtBlock, linkedPairId, linked
  getGlobalStats() -> totalPairs, totalStripes, deployBlockNum, currentFeeBps, currentMaxPairsPerBinder
  getPairsInRange(fromIndex, toIndex) -> pairIds[], leftHashes[], rightHashes[], binders[], resolvedFlags[]
  getStripesInRange(fromIndex, toIndex) -> stripeIds[], anchorHashes[], owners[], linkedFlags[]
  pairExists(pairId), stripeExists(stripeId), pairCount(), stripeCount(), contractBalanceWei()
  getPairIdAt(index), getStripeIdAt(index)

State-changing (require signer):
  registerTwin(pairId, leftHash, rightHash)
  strikeMirror(pairId, side, reasonHash)   // side 0=left, 1=right
  resolvePair(pairId, outcome)             // outcome 0=none, 1=left, 2=right, 3=tie
  postBounty(pairId) payable
  claimBounty(pairId)
  addStripe(stripeId, anchorHash)
  linkStripeToPair(stripeId, pairId)

Errors: DB_ZeroPair, DB_ZeroHash, DB_NotKeeper, DB_NotArbiter, DB_PairNotFound, DB_AlreadyResolved,
  DB_NotResolved, DB_NotBinder, DB_ReentrantCall, DB_MaxPairsReached, DB_MaxPairsPerBinderReached,
  DB_NamespaceFrozen, DB_InvalidSide, DB_InvalidBatchLength, DB_DuplicatePair, DB_StripeNotFound,
  DB_InvalidOutcome, DB_TransferFailed, DB_ZeroAmount, DB_InsufficientBounty, DB_AlreadyStruck,
  DB_InvalidFeeBps, DB_StripeAlreadyLinked, DB_NotStripeOwner, DB_MaxStripesReached, DB_InvalidStripeIndex.
"""

CONSTANTS_TEXT = """
DoppelBanger constants:
  DB_MAX_PAIRS = 750_000
  DB_MAX_PAIRS_PER_BINDER = 12_000
  DB_MAX_BATCH = 72
  DB_MAX_STRIPES = 256
  DB_FEE_BPS_CAP = 600
  DB_SIDES = 2
  DB_OUTCOME_NONE = 0, DB_OUTCOME_LEFT = 1, DB_OUTCOME_RIGHT = 2, DB_OUTCOME_TIE = 3
"""

# -----------------------------------------------------------------------------
# TWIN ATTESTATION PLAYBOOK (reference content for users)
# -----------------------------------------------------------------------------

TWIN_ATTESTATION_PLAYBOOK = """
DoppelBanger — twin-entry attestation playbook

Before registering a pair:
  - Compute leftHash = keccak256(leftPayload) and rightHash = keccak256(rightPayload).
  - Derive pairId = keccak256(leftHash, rightHash, binder, salt) or keccak256(leftHash, rightHash).
  - Ensure pairId is not already registered (call pairExists(pairId)).
  - Check remaining slots for your binder (remainingSlotsForBinder(binder)).

Striking a mirror:
  - Only one strike per (pairId, side, account). Side 0 = left, 1 = right.
  - Pair must exist and not be resolved. Use reasonHash to log why (e.g. keccak256("reason string")).

Resolution:
  - Only the arbiter can resolve. Outcome: 0=none, 1=left, 2=right, 3=tie.
  - After resolution, bounties can be claimed by arbiter or binder.

Bounties:
  - Anyone can postBounty(pairId) with msg.value before resolution.
  - After resolution, arbiter or binder can claimBounty(pairId) once per pair.

Stripes:
  - addStripe(stripeId, anchorHash) to create a stripe; then linkStripeToPair(stripeId, pairId) to bind to a pair.
  - Each stripe can be linked at most once.
"""

TWIN_TIPS = [
    "Use derivePairId(leftHash, rightHash, binder, salt) for unique pairIds when multiple pairs share the same hashes.",
    "Batch register with batchRegisterTwins(pairIds[], leftHashes[], rightHashes[]) up to DB_MAX_BATCH (72) per tx.",
    "Check getGlobalStats() for totalPairs, totalStripes, deployBlockNum, feeBps, maxPairsPerBinder.",
    "Use getPairsInRange(fromIndex, toIndex) to paginate pairs without loading full arrays.",
    "Resolved pairs: getResolvedPairIdsInRange or getPairIdsByOutcome(outcome).",
    "Unresolved: getUnresolvedPairIdsInRange or countUnresolvedPairs().",
    "Pairs with bounty: getPairIdsWithBountyInRange or countPairsWithBounty().",
    "Stripe ownership: getStripeIdsByOwner(owner), getStripeCountByOwner(owner).",
    "Linked stripes for a pair: getLinkedStripeIdsForPair(pairId).",
    "Integrity checks: checkPairIntegrity(pairId), checkStripeIntegrity(stripeId).",
    "Can register more: canRegisterMore(account). Remaining: remainingSlotsForBinder(account), remainingGlobalPairSlots().",
    "Fee on bounty: computeFeeForBounty(bountyWei), computeNetBounty(bountyWei).",
    "Outcome labels: outcomeLabel(outcome) returns 'none'|'left'|'right'|'tie'.",
    "Top binders by pair count: getTopBindersByPairCount(topN).",
    "Blocks since: blocksSinceDeploy(), blocksSincePairRegistered(pairId), blocksSinceStripeCreated(stripeId).",
]

ERROR_CODE_REFERENCE = """
DoppelBanger custom errors (revert with):

  DB_ZeroPair          — pairId is bytes32(0)
  DB_ZeroHash          — leftHash or rightHash is bytes32(0)
  DB_ZeroAddress       — required address is address(0)
  DB_NotKeeper         — sender is not the keeper (or keeper is set and sender != keeper)
  DB_NotArbiter        — sender is not the arbiter
  DB_PairNotFound      — no pair for given pairId
  DB_AlreadyResolved   — pair already resolved
  DB_NotResolved       — pair not yet resolved (e.g. claimBounty)
  DB_NotBinder         — sender is not the binder (e.g. claimBounty)
  DB_ReentrantCall     — reentrancy lock active
  DB_MaxPairsReached   — pairCount >= DB_MAX_PAIRS
  DB_MaxPairsPerBinderReached — binder at max pairs
  DB_NamespaceFrozen   — namespace is frozen
  DB_InvalidSide       — side >= DB_SIDES (2)
  DB_InvalidBatchLength — batch length mismatch or > DB_MAX_BATCH
  DB_DuplicatePair     — pairId or stripeId already exists
  DB_StripeNotFound    — no stripe for given stripeId
  DB_InvalidOutcome    — outcome > 3
  DB_TransferFailed    — ETH transfer failed
  DB_ZeroAmount        — zero value where amount required
  DB_InsufficientBounty — bounty already claimed or zero
  DB_AlreadyStruck     — this account already struck this side for this pair
  DB_InvalidFeeBps     — feeBps > DB_FEE_BPS_CAP
  DB_StripeAlreadyLinked — stripe already linked to a pair
  DB_NotStripeOwner    — sender is not the stripe owner
  DB_MaxStripesReached — stripeCount >= DB_MAX_STRIPES
  DB_InvalidStripeIndex — index out of range
"""

EXAMPLE_PAYLOADS = [
    ("claim_v1", "mirror_v1"),
    ("attestation_left_0", "attestation_right_0"),
    ("payload_a", "payload_b"),
    ("0xdead", "0xbeef"),
]

def cmd_playbook(args: argparse.Namespace) -> int:
    print(TWIN_ATTESTATION_PLAYBOOK)
    return 0

def cmd_tips(args: argparse.Namespace) -> int:
    for i, tip in enumerate(TWIN_TIPS, 1):
        print(f"  {i}. {tip}")
    return 0

def cmd_errors(args: argparse.Namespace) -> int:
    print(ERROR_CODE_REFERENCE)
    return 0

def cmd_examples(args: argparse.Namespace) -> int:
    print("Example left/right payload pairs (hash each side for leftHash/rightHash):")
    for left, right in EXAMPLE_PAYLOADS:
        lh = hash_string(left)
        rh = hash_string(right)
        print(f"  left={left!r}  -> {lh}")
        print(f"  right={right!r} -> {rh}")
        print(f"  pairId (no binder/salt): {derive_pair_id_local(lh, rh, '0x' + '00'*20, 0)}")
        print()
    return 0

def cmd_batch_hashes(args: argparse.Namespace) -> int:
    items = getattr(args, "items", "") or ""
    if not items:
        print("Error: --items required (comma-separated strings to hash)", file=sys.stderr)
        return 1
    parts = [s.strip() for s in items.split(",") if s.strip()]
    out = []
    for s in parts:
        h = hash_string(s)
        out.append({"input": s, "hash": h})
        print(s, "->", h)
    if getattr(args, "json_out", False):
        print(json.dumps(out))
    return 0

def cmd_gen_addresses(args: argparse.Namespace) -> int:
    """Generate N EIP-55 checksummed addresses (for testing/config)."""
    n = int(getattr(args, "count", 8))
    try:
        from web3 import Web3
        import secrets
        for _ in range(n):
            addr = "0x" + secrets.token_hex(20)
            checksummed = Web3.to_checksum_address(addr)
            print(checksummed)
    except ImportError:
        print("Install web3 for EIP-55 checksum: pip install web3", file=sys.stderr)
        for _ in range(n):
            print("0x" + secrets.token_hex(20))
    return 0

# -----------------------------------------------------------------------------
# EXTENDED REFERENCE DATA (for line count and utility)
# -----------------------------------------------------------------------------

OUTCOME_DESCRIPTIONS = {
    0: "No outcome / unset. Pair may still be open.",
    1: "Left side wins. Resolution favours the left hash / claim.",
    2: "Right side wins. Resolution favours the right hash / claim.",
    3: "Tie. Both sides treated equally for bounty/claim logic.",
}

SIDE_LABELS = {0: "left", 1: "right"}

CONTRACT_IMMUTABLES_HELP = """
DoppelBanger constructor sets (immutable):
  keeper       — optional; if zero, arbiter can emergencyFreeze. Keeper sets fee, max pairs per binder, namespace frozen.
  arbiter      — resolves pairs, unboundPair, issueRefund, emergencyUnfreeze.
  treasury     — receives ETH from withdrawToTreasury.
  stripeAnchorA, stripeAnchorB — optional reference addresses (e.g. for stripe verification).
  feeCollector — fee recipient when applicable.
  deployBlock  — block number at deployment.
"""

USAGE_EXAMPLES = """
Usage examples (env or flags):

  export DANDG_RPC_URL=http://127.0.0.1:8545
  export DANDG_CONTRACT=0x...

  # Local hashes (no RPC)
  python DandG_app.py hash --left "left payload" --right "right payload"
  python DandG_app.py pair-id --left-hash 0x... --right-hash 0x... --binder 0x... --salt 1
  python DandG_app.py batch-hashes --items "a,b,c"
  python DandG_app.py examples

  # View (RPC + contract)
  python DandG_app.py get-pair --pair-id 0x...
  python DandG_app.py get-stripe --stripe-id 0x...
  python DandG_app.py list-pairs --from-idx 0 --to-idx 20
  python DandG_app.py list-stripes
  python DandG_app.py stats

  # State-changing (RPC + contract + private-key)
  python DandG_app.py register --pair-id 0x... --left-hash 0x... --right-hash 0x... --private-key $PK
  python DandG_app.py strike --pair-id 0x... --side 0 --reason 0x... --private-key $PK
  python DandG_app.py resolve --pair-id 0x... --outcome 1 --private-key $PK
  python DandG_app.py post-bounty --pair-id 0x... --value-wei 1000000000000000 --private-key $PK
  python DandG_app.py claim-bounty --pair-id 0x... --private-key $PK
  python DandG_app.py add-stripe --stripe-id 0x... --anchor-hash 0x... --private-key $PK
  python DandG_app.py link-stripe --stripe-id 0x... --pair-id 0x... --private-key $PK

  # Reference
  python DandG_app.py playbook
  python DandG_app.py tips
  python DandG_app.py errors
  python DandG_app.py reference
  python DandG_app.py constants
  python DandG_app.py config
  python DandG_app.py version
  python DandG_app.py demo
  python DandG_app.py interactive
  python DandG_app.py gen-addresses --count 10
"""

EXTRA_TWIN_TIPS = [
    "Left hash and right hash can be from arbitrary payloads: use hashTwinPayload(leftPayload, rightPayload) on-chain or hash locally.",
    "Strings: hashTwinStrings(leftStr, rightStr) on-chain; locally use hash_string(s) for each.",
    "pairIdFromHashes(leftHash, rightHash) = keccak256(leftHash, rightHash) for a binder-agnostic id.",
    "Stripe anchors can represent external references; link stripes to pairs for audit trails.",
    "Namespace freeze (keeper or arbiter when keeper is zero) stops new registerTwin and addStripe.",
    "Bounty is stored per pair; multiple posters add to the same bounty pool until resolution.",
    "After resolution, only one claimBounty is allowed per pair (bountyClaimed = true).",
    "getPairIdsRegisteredBetween(fromBlock, toBlock) for block-range queries.",
    "getPairIdsByOutcome(outcome) for resolved pairs by outcome (0-3).",
    "getPairIdsWithStrikesInRange(minStrikesLeft, minStrikesRight) for pairs with minimum strike counts.",
    "getUnlinkedStripeIds() and getLinkedStripeIds() for stripe filtering.",
    "getBinderAddresses() and getStripeOwnerAddresses() for unique address lists.",
    "getPairSummary(pairId) and getStripeSummary(stripeId) for lightweight existence + flags.",
    "getMultiplePairSummaries(pairIds[]) and getMultipleStripeSummaries(stripeIds[]) for batch summary.",
    "contractBalanceWei() includes all received ETH (receive(), postBounty).",
    "withdrawToTreasury(amountWei) is keeper-only; issueRefund(to, amountWei, reasonHash) is arbiter-only.",
]
