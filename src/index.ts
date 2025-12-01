import Fastify from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { SigningService } from './services/signing.service';
import { MPCCoordinatorService } from './services/mpc/mpc-coordinator.service';
import { apiKeyAuth } from './middleware/auth.middleware';
import { 
  rateLimitConfig,
  walletGenerationRateLimit,
  signingRateLimit,
  mpcWalletGenerationRateLimit,
  healthCheckRateLimit,
  readOperationsRateLimit
} from './config/rate-limit.config';
import { isMPCEnabled, mpcConfig } from './config/mpc.config';
import * as dotenv from 'dotenv';

dotenv.config();

const fastify = Fastify({ logger: true });
const signingService = new SigningService();
const mpcCoordinator = new MPCCoordinatorService();

// Register rate limiting
fastify.register(rateLimit, rateLimitConfig);

// ============================================
// HEALTH CHECK
// ============================================
fastify.get('/health', {
  config: { rateLimit: healthCheckRateLimit }
}, async () => {
  return { 
    status: 'ok', 
    service: 'hyperliquid-mpc-kms',
    mpcEnabled: isMPCEnabled(),
    timestamp: new Date().toISOString()
  };
});

// ============================================
// STANDARD WALLET ENDPOINTS
// ============================================

// Generate wallet
fastify.post<{
  Body: { walletId: string; metadata?: any }
}>('/wallets/generate', {
  preHandler: apiKeyAuth,
  config: { rateLimit: walletGenerationRateLimit }
}, async (request, reply) => {
  try {
    const { walletId, metadata } = request.body;
    
    if (!walletId) {
      return reply.code(400).send({ error: 'walletId is required' });
    }

    const wallet = await signingService.generateWallet(walletId, metadata);
    
    return {
      success: true,
      wallet
    };
  } catch (error: any) {
    fastify.log.error(error);
    return reply.code(500).send({ error: error.message });
  }
});

// Sign order
fastify.post<{
  Body: { walletId: string; orderPayload: any }
}>('/wallets/sign-order', {
  preHandler: apiKeyAuth,
  config: { rateLimit: signingRateLimit }
}, async (request, reply) => {
  try {
    const { walletId, orderPayload } = request.body;
    
    if (!walletId || !orderPayload) {
      return reply.code(400).send({ error: 'walletId and orderPayload are required' });
    }

    const result = await signingService.signOrderPayload(walletId, orderPayload);
    
    return {
      success: true,
      ...result
    };
  } catch (error: any) {
    fastify.log.error(error);
    return reply.code(500).send({ error: error.message });
  }
});

// Sign message
fastify.post<{
  Body: { walletId: string; message: string }
}>('/wallets/sign', {
  preHandler: apiKeyAuth,
  config: { rateLimit: signingRateLimit }
}, async (request, reply) => {
  try {
    const { walletId, message } = request.body;
    
    if (!walletId || !message) {
      return reply.code(400).send({ error: 'walletId and message are required' });
    }

    const result = await signingService.signMessage({ walletId, message });
    
    return {
      success: true,
      ...result
    };
  } catch (error: any) {
    fastify.log.error(error);
    return reply.code(500).send({ error: error.message });
  }
});

// Get public key
fastify.get<{
  Params: { walletId: string }
}>('/wallets/:walletId/public-key', {
  config: { rateLimit: readOperationsRateLimit }
}, async (request, reply) => {
  try {
    const { walletId } = request.params;
    const publicKey = await signingService.getPublicKey(walletId);
    
    return {
      success: true,
      walletId,
      publicKey
    };
  } catch (error: any) {
    fastify.log.error(error);
    return reply.code(404).send({ error: error.message });
  }
});

// ============================================
// MPC ENDPOINTS
// ============================================

// MPC Status
fastify.get('/mpc/status', {
  config: { rateLimit: healthCheckRateLimit }
}, async () => {
  return {
    mpcEnabled: isMPCEnabled(),
    nodes: mpcConfig.nodes,
    threshold: mpcConfig.threshold,
    algorithm: 'AWS KMS Threshold Signatures',
    description: `${mpcConfig.threshold}-of-${mpcConfig.nodes} distributed signing`,
    security: 'Private keys never exist in full anywhere'
  };
});

// Generate MPC wallet
fastify.post<{
  Body: { walletId: string; metadata?: any }
}>('/mpc/wallets/generate', {
  preHandler: apiKeyAuth,
  config: { rateLimit: mpcWalletGenerationRateLimit }
}, async (request, reply) => {
  try {
    const { walletId, metadata } = request.body;
    
    if (!walletId) {
      return reply.code(400).send({ error: 'walletId is required' });
    }

    if (!isMPCEnabled()) {
      return reply.code(400).send({ 
        error: 'MPC is not enabled. Check MPC_NODES configuration.' 
      });
    }

    const wallet = await mpcCoordinator.generateMPCWallet(walletId);
    
    return {
      success: true,
      wallet: {
        walletId: wallet.walletId,
        publicKey: wallet.publicKey,  // Changed from aggregatedPublicKey
        shareIds: wallet.shareIds,
        createdAt: new Date().toISOString(),
        mpcEnabled: true,
        tssMethod: 'Multi-round ECDSA (GG20-inspired)',
        metadata
      }
    };
  } catch (error: any) {
    fastify.log.error(error);
    return reply.code(500).send({ error: error.message });
  }
});

// Sign with MPC
fastify.post<{
  Body: { walletId: string; orderPayload: any }
}>('/mpc/wallets/sign-order', {
  preHandler: apiKeyAuth,
  config: { rateLimit: signingRateLimit }
}, async (request, reply) => {
  try {
    const { walletId, orderPayload } = request.body;
    
    if (!walletId || !orderPayload) {
      return reply.code(400).send({ error: 'walletId and orderPayload are required' });
    }

    if (!isMPCEnabled()) {
      return reply.code(400).send({ error: 'MPC is not enabled' });
    }

    // Serialize order payload
    const message = Buffer.from(JSON.stringify(orderPayload), 'utf-8');
    
    // Sign using TRUE threshold signatures (no key reconstruction!)
    const result = await mpcCoordinator.signWithMPC({
      walletId,
      message
    });
    
    return {
      success: true,
      signature: result.signature,
      walletId,
      mpcSigning: true,
      method: result.signingMethod,
      security: 'Private key NEVER reconstructed - TSS multi-round protocol'
    };
  } catch (error: any) {
    fastify.log.error(error);
    return reply.code(500).send({ error: error.message });
  }
});

// ============================================
// START SERVER
// ============================================
const start = async () => {
  try {
    const port = parseInt(process.env.PORT || '3000');
    await fastify.listen({ port, host: '0.0.0.0' });
    
    console.log('\n═══════════════════════════════════════════════════');
    console.log('  Hyperliquid MPC KMS Service Started');
    console.log('═══════════════════════════════════════════════════');
    console.log(`  Server: http://localhost:${port}`);
    console.log(`  MPC Enabled: ${isMPCEnabled()}`);
    console.log(`  Threshold: ${mpcConfig.threshold} of ${mpcConfig.nodes}`);
    console.log('═══════════════════════════════════════════════════\n');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
