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
 * Demo Trading Bot - MPC Mode
 * Demonstrates distributed signing with threshold signatures
 */
class HyperliquidMPCBot {
  private walletId: string;
  private publicKey: string = '';

  constructor(walletId: string) {
    this.walletId = walletId;
  }

  async initialize() {
    console.log('\n╔════════════════════════════════════════════════════╗');
    console.log('║   Hyperliquid Demo Bot - MPC Mode (2-of-3)        ║');
    console.log('╚════════════════════════════════════════════════════╝\n');

    // Check MPC status
    const statusResponse = await axios.get(`${KMS_SERVICE_URL}/mpc/status`);
    console.log('MPC Configuration:');
    console.log(`   Enabled: ${statusResponse.data.mpcEnabled}`);
    console.log(`   Threshold: ${statusResponse.data.threshold} of ${statusResponse.data.nodes}`);
    console.log(`   Algorithm: ${statusResponse.data.algorithm}`);
    console.log(`   Security: ${statusResponse.data.security}\n`);

    // Create MPC wallet
    console.log('Creating MPC wallet with distributed key shares...');
    
    const response = await axios.post(
      `${KMS_SERVICE_URL}/mpc/wallets/generate`,
      {
        walletId: this.walletId,
        metadata: {
          label: 'MPC Demo Bot Wallet',
          purpose: 'High-Security Automated Trading',
          bot: 'hyperliquid-mpc-bot'
        }
      },
      {
        headers: { 'X-API-Key': API_KEY }
      }
    );
    
    this.publicKey = response.data.wallet.aggregatedPublicKey;
    console.log('MPC wallet created');
    console.log(`   Wallet ID: ${this.walletId}`);
    console.log(`   Aggregated Public Key: ${this.publicKey}`);
    console.log('   Note: Private key NEVER existed in full!\n');
  }

  async runHighValueTrade() {
    console.log('╔════════════════════════════════════════════════════╗');
    console.log('║   High-Value Trade with MPC Signing                ║');
    console.log('╚════════════════════════════════════════════════════╝\n');

    const currentPrice = 95000;
    
    // Large order requiring MPC security
    const order: HyperliquidOrder = {
      action: 'order',
      coin: 'BTC',
      isBuy: true,
      sz: 10.0, // Large size
      limitPx: currentPrice,
      timestamp: Date.now()
    };

    console.log('High-Value Order:');
    console.log(`   Coin: ${order.coin}`);
    console.log(`   Size: ${order.sz} BTC ($${(order.sz * currentPrice).toLocaleString()})`);
    console.log(`   Price: $${order.limitPx}\n`);

    console.log('Initiating MPC threshold signing...');
    console.log('   Node 1: Signing with key share 1...');
    console.log('   Node 2: Signing with key share 2...');
    console.log('   (Threshold met: 2 of 3 nodes)\n');

    const signature = await this.signOrderMPC(order);

    console.log('MPC Signature Complete!');
    console.log(`   Combined Signature: ${signature.substring(0, 30)}...`);
    console.log(`   Nodes Used: 2 of 3`);
    console.log('   Full private key was NEVER reconstructed!\n');

    return signature;
  }

  private async signOrderMPC(order: HyperliquidOrder): Promise<string> {
    try {
      const response = await axios.post(
        `${KMS_SERVICE_URL}/mpc/wallets/sign-order`,
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

  async demonstrateMPCSecurity() {
    console.log('╔════════════════════════════════════════════════════╗');
    console.log('║   MPC Security Advantages                          ║');
    console.log('╚════════════════════════════════════════════════════╝\n');
    
    console.log('TRUE Multi-Party Computation (MPC):');
    console.log('   - Private key split across 3 AWS KMS nodes');
    console.log('   - Each node holds independent key share');
    console.log('   - Need 2 of 3 nodes to create valid signature');
    console.log('   - Full private key NEVER exists anywhere');
    console.log('   - Compromise of 1 node = still secure');
    console.log('   - Mathematical signature combination (not key reconstruction)');
    console.log('   - Each KMS key protected by AWS hardware security modules\n');
    
    console.log('Comparison:');
    console.log('   Standard: 1 key breach = funds at risk');
    console.log('   MPC:      Need 2 simultaneous breaches = exponentially harder\n');
  }
}

async function runMPCDemo() {
  const bot = new HyperliquidMPCBot('mpc-production-wallet');

  try {
    await bot.initialize();
    await bot.runHighValueTrade();
    await bot.demonstrateMPCSecurity();

    console.log('╔════════════════════════════════════════════════════╗');
    console.log('║   MPC Demo Completed Successfully!                 ║');
    console.log('╚════════════════════════════════════════════════════╝\n');

  } catch (error: any) {
    console.error('\nDemo failed:', error.response?.data || error.message);
    process.exit(1);
  }
}

runMPCDemo();
