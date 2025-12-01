import { kmsClient, secretsClient, SECRETS_PREFIX } from '../config/aws.config';
import { CreateSecretCommand, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import * as nacl from 'tweetnacl';
import * as crypto from 'crypto';

export interface Wallet {
  walletId: string;
  publicKey: string;
  createdAt: string;
  metadata?: any;
}

export interface SignatureResult {
  signature: string;
  publicKey: string;
  walletId: string;
}

/**
 * Signing Service for Hyperliquid orders
 * Uses Ed25519 (tweetnacl) for Hyperliquid compatibility
 */
export class SigningService {
  
  /**
   * Generate new wallet (Ed25519 keypair)
   */
  async generateWallet(walletId: string, metadata?: any): Promise<Wallet> {
    console.log(`\nGenerating wallet: ${walletId}`);
    
    // Generate Ed25519 keypair
    const keyPair = nacl.sign.keyPair();
    
    // Store encrypted private key in AWS Secrets Manager
    await this.storePrivateKey(walletId, keyPair.secretKey);
    
    const publicKey = '0x' + Buffer.from(keyPair.publicKey).toString('hex');
    
    console.log(`Wallet created: ${publicKey}\n`);
    
    return {
      walletId,
      publicKey,
      createdAt: new Date().toISOString(),
      metadata
    };
  }
  
  /**
   * Sign Hyperliquid order payload
   */
  async signOrderPayload(walletId: string, orderPayload: any): Promise<SignatureResult> {
    console.log(`\nSigning order for: ${walletId}`);
    
    // Get private key from AWS Secrets Manager
    const privateKey = await this.getPrivateKey(walletId);
    
    try {
      // Serialize order payload
      const message = JSON.stringify(orderPayload);
      const messageBytes = Buffer.from(message, 'utf-8');
      
      // Sign with Ed25519
      const signature = nacl.sign.detached(messageBytes, privateKey);
      const signatureHex = '0x' + Buffer.from(signature).toString('hex');
      
      // Get public key for response
      const keyPair = nacl.sign.keyPair.fromSecretKey(privateKey);
      const publicKey = '0x' + Buffer.from(keyPair.publicKey).toString('hex');
      
      console.log(`Order signed successfully\n`);
      
      return {
        signature: signatureHex,
        publicKey,
        walletId
      };
    } finally {
      // CRITICAL: Wipe private key from memory
      privateKey.fill(0);
    }
  }
  
  /**
   * Sign arbitrary message
   */
  async signMessage(request: { walletId: string; message: string }): Promise<SignatureResult> {
    const { walletId, message } = request;
    console.log(`\nSigning message for: ${walletId}`);
    
    const privateKey = await this.getPrivateKey(walletId);
    
    try {
      const messageBytes = Buffer.from(message, 'utf-8');
      const signature = nacl.sign.detached(messageBytes, privateKey);
      const signatureHex = '0x' + Buffer.from(signature).toString('hex');
      
      const keyPair = nacl.sign.keyPair.fromSecretKey(privateKey);
      const publicKey = '0x' + Buffer.from(keyPair.publicKey).toString('hex');
      
      console.log(`Message signed\n`);
      
      return {
        signature: signatureHex,
        publicKey,
        walletId
      };
    } finally {
      privateKey.fill(0);
    }
  }
  
  /**
   * Get public key for wallet
   */
  async getPublicKey(walletId: string): Promise<string> {
    const privateKey = await this.getPrivateKey(walletId);
    
    try {
      const keyPair = nacl.sign.keyPair.fromSecretKey(privateKey);
      return '0x' + Buffer.from(keyPair.publicKey).toString('hex');
    } finally {
      privateKey.fill(0);
    }
  }
  
  /**
   * Store private key in AWS Secrets Manager (encrypted at rest)
   */
  private async storePrivateKey(walletId: string, secretKey: Uint8Array): Promise<void> {
    const secretName = `${SECRETS_PREFIX}${walletId}`;
    const secretValue = Buffer.from(secretKey).toString('base64');
    
    const command = new CreateSecretCommand({
      Name: secretName,
      SecretString: secretValue,
      Description: `Private key for Hyperliquid wallet ${walletId}`,
      Tags: [
        { Key: 'WalletId', Value: walletId },
        { Key: 'Type', Value: 'Ed25519' }
      ]
    });
    
    await secretsClient.send(command);
  }
  
  /**
   * Retrieve private key from AWS Secrets Manager
   * Key is decrypted by AWS KMS automatically
   */
  private async getPrivateKey(walletId: string): Promise<Uint8Array> {
    const secretName = `${SECRETS_PREFIX}${walletId}`;
    
    const command = new GetSecretValueCommand({ SecretId: secretName });
    const response = await secretsClient.send(command);
    
    if (!response.SecretString) {
      throw new Error(`Private key not found for wallet: ${walletId}`);
    }
    
    return Uint8Array.from(Buffer.from(response.SecretString, 'base64'));
  }
  
  /**
   * List all wallets
   */
  async listWallets(): Promise<string[]> {
    // Simplified - in production, use ListSecrets API
    return [];
  }
}
