import { hashSync } from 'bcrypt';
import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';

import app from './app';
import { config } from './config';
import { createUser, resetUsers } from './repositories/userRepository';

interface ApiErrorBody {
  error: string;
}

interface LoginSuccessBody {
  accessToken: string;
  tokenType: string;
  role: string;
}

const DEACTIVATED_EMAIL = 'deactivated@library.test';
const DEACTIVATED_PASSWORD = 'Deactivated123!';
const ACTIVE_EMAIL = 'active@library.test';
const ACTIVE_PASSWORD = 'ActivePassword123!';
const PASSWORD_SALT_ROUNDS = 10;

function seedUsers(): void {
  createUser({
    memberId: 99,
    email: DEACTIVATED_EMAIL,
    passwordHash: hashSync(DEACTIVATED_PASSWORD, PASSWORD_SALT_ROUNDS),
    role: 'member',
    active: false,
  });
  createUser({
    memberId: 100,
    email: ACTIVE_EMAIL,
    passwordHash: hashSync(ACTIVE_PASSWORD, PASSWORD_SALT_ROUNDS),
    role: 'member',
  });
}

beforeEach(() => {
  resetUsers();
  seedUsers();
});

describe('POST /auth/login for a deactivated account', () => {
  it('refuses a correct password with 401 Account is deactivated and no token', async () => {
    const res = await request(app)
      .post('/auth/login')
      .set('x-service-key', config.serviceKey)
      .send({ email: DEACTIVATED_EMAIL, password: DEACTIVATED_PASSWORD });

    expect(res.status).toBe(401);
    expect((res.body as ApiErrorBody).error).toBe('Account is deactivated');
    expect(res.body).not.toHaveProperty('accessToken');
  });

  it('still answers Invalid credentials for a wrong password on a deactivated account', async () => {
    const res = await request(app)
      .post('/auth/login')
      .set('x-service-key', config.serviceKey)
      .send({ email: DEACTIVATED_EMAIL, password: 'WrongPassword123!' });

    expect(res.status).toBe(401);
    expect((res.body as ApiErrorBody).error).toBe('Invalid credentials');
    expect(res.body).not.toHaveProperty('accessToken');
  });

  it('issues a token for an active account', async () => {
    const res = await request(app)
      .post('/auth/login')
      .set('x-service-key', config.serviceKey)
      .send({ email: ACTIVE_EMAIL, password: ACTIVE_PASSWORD });

    expect(res.status).toBe(200);
    const body = res.body as LoginSuccessBody;
    expect(body.tokenType).toBe('Bearer');
    expect(body.role).toBe('member');
    expect(typeof body.accessToken).toBe('string');
    expect(body.accessToken.split('.')).toHaveLength(3);
  });
});
