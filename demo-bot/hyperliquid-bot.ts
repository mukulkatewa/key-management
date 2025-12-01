import axios from 'axios';
import * as dotenv from 'dotenv';

dotenv.config({ path: '../.env' });

const KMS_SERVICE_URL = process.env.KMS_SERVICE_URL || 'http://localhost:3000';
const API_KEY = process.env.API_KEY || 'dev_api_key_change_in_production';

interface HyperliquidOrder {
  action: string;
  coin: string;
  isBuy: boolean;
  sz: number;
  limitPx: number;
  timestamp: number;
}

/**
 * Demo Trading Bot - Standard KMS Signing
 * Demonstrates how trading bots integrate with KMS service
 */
class HyperliquidDemoBot {
  private walletId: string;
  private publicKey: string = '';

  constructor(walletId: string) {
    this.walletId = walletId;
  }

  /**
   * Initialize bot - create or load wallet
   */
  async initialize() {
    console.log('\n╔════════════════════════════════════════════════════╗');
    console.log('║   Hyperliquid Demo Bot - Standard KMS Mode        ║');
    console.log('╚════════════════════════════════════════════════════╝\n');

    try {
      // Try to get existing wallet
      const response = await axios.get(
        `${KMS_SERVICE_URL}/wallets/${this.walletId}/public-key`
      );
      this.publicKey = response.data.publicKey;
      console.log('Loaded existing wallet');
      console.log(`   Wallet ID: ${this.walletId}`);
      console.log(`   Public Key: ${this.publicKey}\n`);
    } catch (error) {
      // Wallet doesn't exist, create new one
      console.log('Wallet not found. Creating new wallet...');
      const response = await axios.post(
        `${KMS_SERVICE_URL}/wallets/generate`,
        {
          walletId: this.walletId,
          metadata: {
            label: 'Demo Bot Wallet',
            purpose: 'Automated Trading Demo',
            bot: 'hyperliquid-demo-bot'
          }
        },
        {
          headers: { 'X-API-Key': API_KEY }
        }
      );
      this.publicKey = response.data.wallet.publicKey;
      console.log('Created new wallet');
      console.log(`   Wallet ID: ${this.walletId}`);
      console.log(`   Public Key: ${this.publicKey}\n`);
    }
  }

  /**
   * Simulate market making strategy
   */
  async runMarketMakingStrategy() {
    console.log('╔════════════════════════════════════════════════════╗');
    console.log('║   Market Making Strategy Demo                      ║');
    console.log('╚════════════════════════════════════════════════════╝\n');

    // Simulate getting market data
    const currentPrice = 95000 + Math.random() * 1000; // BTC price
    console.log(`Current BTC Price: $${currentPrice.toFixed(2)}\n`);

    // Create buy order (bid)
    const buyOrder: HyperliquidOrder = {
      action: 'order',
      coin: 'BTC',
      isBuy: true,
      sz: 0.1,
      limitPx: Math.floor(currentPrice - 100),
      timestamp: Date.now()
    };

    // Create sell order (ask)
    const sellOrder: HyperliquidOrder = {
      action: 'order',
      coin: 'BTC',
      isBuy: false,
      sz: 0.1,
      limitPx: Math.floor(currentPrice + 100),
      timestamp: Date.now()
    };

    console.log('Placing Orders:');
    console.log(`   BUY:  ${buyOrder.sz} BTC @ $${buyOrder.limitPx}`);
    console.log(`   SELL: ${sellOrder.sz} BTC @ $${sellOrder.limitPx}\n`);

    // Sign orders using KMS (NO PRIVATE KEY EXPOSED!)
    console.log('Requesting signatures from KMS...\n');
    
    const buySignature = await this.signOrder(buyOrder);
    const sellSignature = await this.signOrder(sellOrder);

    console.log('Orders Signed Successfully!');
    console.log(`   Buy Order Signature: ${buySignature.substring(0, 30)}...`);
    console.log(`   Sell Order Signature: ${sellSignature.substring(0, 30)}...`);

    console.log('\nOrders Ready to Submit to Hyperliquid Exchange');
    console.log('   (In production, would send to Hyperliquid API here)\n');

    return { buySignature, sellSignature };
  }

  /**
   * Sign order using KMS service
   */
  private async signOrder(order: HyperliquidOrder): Promise<string> {
    try {
      const response = await axios.post(
        `${KMS_SERVICE_URL}/wallets/sign-order`,
        {
          walletId: this.walletId,
          orderPayload: order
        },
        {
          headers: { 'X-API-Key': API_KEY }
        }
      );

      return response.data.signature;
    } catch (error: any) {
      console.error('Failed to sign order:', error.response?.data || error.message);
      throw error;
    }
  }

  /**
   * Demonstrate security features
   */
  async demonstrateSecurity() {
    console.log('╔════════════════════════════════════════════════════╗');
    console.log('║   Security Features                                ║');
    console.log('╚════════════════════════════════════════════════════╝\n');
    
    console.log('Security Features:');
    console.log('   - Private keys stored encrypted in AWS Secrets Manager');
    console.log('   - Keys decrypted only in-memory during signing');
    console.log('   - Keys wiped from memory immediately after use');
    console.log('   - No private keys in logs, code, or environment variables');
    console.log('   - API authentication required for all operations');
    console.log('   - AWS KMS encrypts data at rest');
    console.log('   - Rate limiting prevents abuse\n');
  }
}

/**
 * Main demo execution
 */
async function runDemo() {
  const bot = new HyperliquidDemoBot('production-bot-wallet');

  try {
    // Step 1: Initialize
    await bot.initialize();

    // Step 2: Run strategy
    await bot.runMarketMakingStrategy();

    // Step 3: Show security features
    await bot.demonstrateSecurity();

    console.log('╔════════════════════════════════════════════════════╗');
    console.log('║   Demo Completed Successfully!                     ║');
    console.log('╚════════════════════════════════════════════════════╝\n');

  } catch (error: any) {
    console.error('\nDemo failed:', error.response?.data || error.message);
    process.exit(1);
  }
}

// Run the demo
runDemo();
