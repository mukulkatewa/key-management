import { TSSCoordinatorService } from './tss-coordinator.service';
import { mpcConfig } from '../../config/mpc.config';

export interface MPCSignRequest {
  walletId: string;
  message: Buffer;
}

/**
 * TRUE MPC Coordinator using TSS
 * Private key NEVER reconstructed, not even in memory
 */
export class MPCCoordinatorService {
  private tssCoordinator: TSSCoordinatorService;
  
  constructor() {
    this.tssCoordinator = new TSSCoordinatorService();
  }
  
  /**
   * Generate MPC wallet using TSS DKG
   * Full private key is NEVER created
   */
  async generateMPCWallet(walletId: string): Promise<{
    walletId: string;
    publicKey: string;
    shareIds: number[];
  }> {
    const result = await this.tssCoordinator.performDKG(
      walletId,
      mpcConfig.threshold,
      mpcConfig.nodes
    );
    
    // Initialize TSS parties with their shares
    await this.tssCoordinator.initializeParties(
      walletId,
      mpcConfig.threshold,
      mpcConfig.nodes
    );
    
    return {
      walletId,
      publicKey: result.publicKey,
      shareIds: result.shareIds
    };
  }
  
  /**
   * Sign message using TSS multi-round protocol
   * Key is NEVER reconstructed
   */
  async signWithMPC(request: MPCSignRequest): Promise<{
    signature: string;
    signingMethod: string;
  }> {
    const { walletId, message } = request;
    
    // Use threshold number of parties (2 out of 3)
    const signingParties = [1, 2];
    
    // Perform TSS signing
    const result = await this.tssCoordinator.signWithTSS(
      walletId,
      message,
      signingParties
    );
    
    // Combine r and s into single signature
    const signature = '0x' + result.signature.r + result.signature.s;
    
    return {
      signature,
      signingMethod: result.method
    };
  }
}
