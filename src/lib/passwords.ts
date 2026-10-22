import { compare, hash, hashSync } from 'bcrypt';

const PASSWORD_SALT_ROUNDS = 10;

export function hashPassword(plain: string): Promise<string> {
  return hash(plain, PASSWORD_SALT_ROUNDS);
}

export function verifyPassword(plain: string, passwordHash: string): Promise<boolean> {
  return compare(plain, passwordHash);
}

// A real bcrypt hash so an unknown email still pays the compare cost at login.
export const DUMMY_PASSWORD_HASH: string = hashSync(
  'dummy-password-never-matches',
  PASSWORD_SALT_ROUNDS,
);
