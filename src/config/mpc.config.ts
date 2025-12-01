import * as dotenv from 'dotenv';

dotenv.config();

// TRUE MPC Configuration
export const mpcConfig = {
  // Number of KMS nodes (each with independent key share)
  nodes: parseInt(process.env.MPC_NODES || '3'),
  
  // Threshold: need N signatures to create valid signature
  threshold: parseInt(process.env.MPC_THRESHOLD || '2'),
  
  // Each node stores: AWS KMS key ID
  nodeConfig: {
    node1: process.env.AWS_KMS_KEY_NODE_1!,
    node2: process.env.AWS_KMS_KEY_NODE_2!,
    node3: process.env.AWS_KMS_KEY_NODE_3!,
  }
};

export const isMPCEnabled = () => mpcConfig.nodes >= 2;
