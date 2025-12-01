#!/bin/bash

echo "╔════════════════════════════════════════════════════╗"
echo "║   MPC Integration Test                             ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

API_KEY="dev_api_key_change_in_production"
BASE_URL="http://localhost:3000"

# Test 1: MPC Status
echo "Test 1: MPC Status"
curl -s "$BASE_URL/mpc/status" | jq .
echo ""

# Test 2: Generate MPC wallet
echo "Test 2: Generate MPC Wallet"
MPC_WALLET_RESPONSE=$(curl -s -X POST "$BASE_URL/mpc/wallets/generate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"walletId":"mpc-test-wallet-1","metadata":{"security":"high"}}')
echo "$MPC_WALLET_RESPONSE" | jq .
echo ""

# Test 3: Sign order with MPC
echo "Test 3: Sign Order with MPC (2-of-3 threshold)"
curl -s -X POST "$BASE_URL/mpc/wallets/sign-order" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "walletId":"mpc-test-wallet-1",
    "orderPayload":{
      "action":"order",
      "coin":"BTC",
      "isBuy":true,
      "sz":10.0,
      "limitPx":95000,
      "timestamp":'"$(date +%s000)"'
    }
  }' | jq .
echo ""

echo "All MPC tests completed!"
