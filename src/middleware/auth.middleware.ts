import { FastifyRequest, FastifyReply } from 'fastify';
import * as dotenv from 'dotenv';

dotenv.config();

const API_KEY = process.env.API_KEY || 'dev_api_key_change_in_production';

/**
 * API Key authentication middleware
 */
export async function apiKeyAuth(request: FastifyRequest, reply: FastifyReply) {
  const apiKey = request.headers['x-api-key'];
  
  if (!apiKey || apiKey !== API_KEY) {
    return reply.code(401).send({ 
      error: 'Unauthorized: Invalid or missing API key',
      hint: 'Include X-API-Key header with your request'
    });
  }
}
