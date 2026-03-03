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
