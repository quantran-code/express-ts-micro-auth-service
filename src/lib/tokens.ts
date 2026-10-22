import { createHmac } from 'node:crypto';
import { config } from '../config';
import type { User, UserRole } from '../repositories/userRepository';

export interface AccessTokenPayload {
  sub: number;
  role: UserRole;
  memberId: number | null;
  iat: number;
  exp: number;
}

const TOKEN_HEADER = { alg: 'HS256', typ: 'JWT' };

function base64UrlEncode(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

export function signAccessToken(user: User): string {
  const iat = Math.floor(Date.now() / 1000);
  const payload: AccessTokenPayload = {
    sub: user.id,
    role: user.role,
    memberId: user.memberId,
    iat,
    exp: iat + config.accessTokenTtlSeconds,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(TOKEN_HEADER));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = createHmac('sha256', config.jwtSecret).update(signingInput).digest('base64url');

  return `${signingInput}.${signature}`;
}
