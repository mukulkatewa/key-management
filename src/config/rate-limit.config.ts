export const rateLimitConfig = {
  max: 100,
  timeWindow: '5 minutes'
};

export const walletGenerationRateLimit = {
  max: 5,
  timeWindow: '5 minutes'
};

export const signingRateLimit = {
  max: 50,
  timeWindow: '5 minutes'
};

export const mpcWalletGenerationRateLimit = {
  max: 3,
  timeWindow: '5 minutes'
};

export const readOperationsRateLimit = {
  max: 200,
  timeWindow: '5 minutes'
};

export const healthCheckRateLimit = {
  max: 1000,
  timeWindow: '5 minutes'
};
