import { KMSClient, CreateKeyCommand } from '@aws-sdk/client-kms';
import * as dotenv from 'dotenv';

dotenv.config();

const kmsClient = new KMSClient({ region: process.env.AWS_REGION || 'us-east-1' });

async function setupMPCNodes() {
  console.log('\nSetting up MPC Nodes...\n');
  
  const nodeKeys = [];
  
  for (let i = 1; i <= 3; i++) {
    const command = new CreateKeyCommand({
      KeySpec: 'ECC_SECG_P256K1', // secp256k1 for Hyperliquid
      KeyUsage: 'SIGN_VERIFY',
      Description: `MPC Node ${i} - Hyperliquid Signing`,
      Tags: [
        { TagKey: 'Purpose', TagValue: `MPC-Node-${i}` },
        { TagKey: 'Project', TagValue: 'HyperliquidMPC' }
      ]
    });
    
    const response = await kmsClient.send(command);
    const keyId = response.KeyMetadata?.KeyId;
    
    console.log(`✓ Node ${i} Key Created: ${keyId}`);
    nodeKeys.push(keyId);
  }
  
  console.log('\nAdd these to your .env file:\n');
  nodeKeys.forEach((keyId, i) => {
    console.log(`AWS_KMS_KEY_NODE_${i + 1}=${keyId}`);
  });
}

setupMPCNodes();
