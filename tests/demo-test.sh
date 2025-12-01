#!/bin/bash

echo "╔════════════════════════════════════════════════════╗"
echo "║   Standard KMS Integration Test                    ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

API_KEY="dev_api_key_change_in_production"
BASE_URL="http://localhost:3000"

# Test 1: Health check
echo "Test 1: Health Check"
curl -s "$BASE_URL/health" | jq .
echo ""

# Test 2: Generate wallet
echo "Test 2: Generate Wallet"
WALLET_RESPONSE=$(curl -s -X POST "$BASE_URL/wallets/generate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"walletId":"test-wallet-1","metadata":{"test":true}}')
echo "$WALLET_RESPONSE" | jq .
PUBLIC_KEY=$(echo "$WALLET_RESPONSE" | jq -r '.wallet.publicKey')
echo ""

# Test 3: Get public key
echo "Test 3: Get Public Key"
curl -s "$BASE_URL/wallets/test-wallet-1/public-key" | jq .
echo ""

# Test 4: Sign order
echo "Test 4: Sign Order"
curl -s -X POST "$BASE_URL/wallets/sign-order" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "walletId":"test-wallet-1",
    "orderPayload":{
      "action":"order",
      "coin":"BTC",
      "isBuy":true,
      "sz":0.1,
      "limitPx":95000,
      "timestamp":'"$(date +%s000)"'
    }
  }' | jq .
echo ""

echo "All tests completed!"
