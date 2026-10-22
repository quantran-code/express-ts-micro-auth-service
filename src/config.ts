export interface ServiceConfig {
  port: number;
  env: string;
  serviceKey: string;
  memberServiceUrl: string;
  jwtSecret: string;
  accessTokenTtlSeconds: number;
}

export const config: ServiceConfig = {
  port: Number(process.env.PORT) || 3001,
  env: process.env.NODE_ENV || 'development',
  serviceKey: process.env.SERVICE_KEY || 'dev-service-key',
  memberServiceUrl: process.env.MEMBER_SERVICE_URL || 'http://localhost:3003',
  jwtSecret: process.env.JWT_SECRET || 'development-insecure-secret',
  accessTokenTtlSeconds: Number(process.env.ACCESS_TOKEN_TTL_SECONDS) || 3600,
};
