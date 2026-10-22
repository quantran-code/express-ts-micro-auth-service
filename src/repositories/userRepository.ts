import { hashSync } from 'bcrypt';

export type UserRole = 'member' | 'librarian';

export interface User {
  id: number;
  memberId: number | null;
  email: string;
  passwordHash: string;
  role: UserRole;
  active: boolean;
}

export interface CreateUserInput {
  memberId: number | null;
  email: string;
  passwordHash: string;
  role: UserRole;
  active?: boolean;
}

const SEEDED_LIBRARIAN_EMAIL = 'librarian@library.test';
const SEEDED_LIBRARIAN_PASSWORD = 'Librarian123!';
const PASSWORD_SALT_ROUNDS = 10;

let users: User[] = [];
let nextId = 1;

export function createUser(input: CreateUserInput): User {
  const user: User = {
    id: nextId,
    memberId: input.memberId,
    email: input.email.trim().toLowerCase(),
    passwordHash: input.passwordHash,
    role: input.role,
    active: input.active ?? true,
  };
  nextId += 1;
  users.push(user);
  return user;
}

export function findUserByEmail(email: string): User | undefined {
  const needle = email.trim().toLowerCase();
  return users.find((user) => user.email.toLowerCase() === needle);
}

export function findUserByMemberId(memberId: number): User | undefined {
  return users.find((user) => user.memberId === memberId);
}

export function resetUsers(): void {
  users = [];
  nextId = 1;
  createUser({
    memberId: null,
    email: SEEDED_LIBRARIAN_EMAIL,
    passwordHash: hashSync(SEEDED_LIBRARIAN_PASSWORD, PASSWORD_SALT_ROUNDS),
    role: 'librarian',
  });
}

// Seed on module load so the librarian exists on boot without touching server.ts.
resetUsers();
