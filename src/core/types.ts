// Source of truth for these types: doc/freeauth-architecture.md
// Every interface and method signature below is defined there. Do not modify this
// file without updating that document first.

export interface UserRecord {
  id: string; // always a string — adapter must convert ObjectId/number/uuid itself
  email: string;
  name: string;
  password: string | null; // hash, never plaintext; null for OAuth-only users who never set one

  isAccountVerified: boolean;

  // 'local' for users created via registerUser (the default for all pre-existing
  // records); 'google'/'github' for users created via createOAuthUser.
  provider: 'local' | 'google' | 'github';
  providerId: string | null; // provider's subject id (`sub` for Google, numeric user id for GitHub), null for local users

  verifyOTP: string | null; // hash of the OTP, never plaintext
  verifyOTPExpire: number | null; // epoch ms
  verifyAttempts: number;
  verifyLockUntil: Date | null;

  resetOTP: string | null;
  resetOTPExpire: number | null;
  resetAttempts: number;
  resetLockUntil: Date | null;
}

export interface SessionRecord {
  userId: string;
  token: string;
  isRevoked: boolean;
  expiresAt: Date;
  createdAt: Date;
}

export interface UserAdapter {
  findByEmail(email: string): Promise<UserRecord | null>;
  findById(id: string): Promise<UserRecord | null>;

  create(data: {
    email: string;
    name: string;
    password: string; // already hashed by core before calling this
    verifyOTP: string;
    verifyOTPExpire: number;
  }): Promise<UserRecord>;

  /**
   * Create an OAuth-only user. Unlike create(), this sets no password (OAuth users
   * authenticate via their provider, never via a local password) and marks the
   * account verified immediately — the provider already verified the email, so no
   * OTP flow is needed. Called only by core's OAuth logins for first-time OAuth users.
   */
  createOAuthUser(data: {
    email: string;
    name: string;
    provider: 'google' | 'github';
    providerId: string;
  }): Promise<UserRecord>;

  updatePassword(id: string, hashedPassword: string): Promise<void>;

  markVerified(id: string): Promise<void>;

  setVerifyOTP(id: string, otp: string, expiresAt: number): Promise<void>;
  setResetOTP(id: string, otp: string, expiresAt: number): Promise<void>;
  clearVerifyOTP(id: string): Promise<void>;
  clearResetOTP(id: string): Promise<void>;

  /**
   * Increment a flow's OTP attempt counter and return the authoritative
   * post-increment count. The core uses this return value to decide whether
   * the lockout threshold (currently 5) has been reached — it must never
   * guess the count from a record read at the start of the flow and assume
   * no concurrent attempts happened. Two concurrent wrong-OTP submissions
   * could both read count=4, and neither would trigger the lock. The
   * adapter's increment must be the single source of truth for the count,
   * the same way revoke() is the single source of truth for revocation state.
   */
  incrementOtpAttempts(id: string, type: 'verify' | 'reset'): Promise<number>;
  setOtpLock(id: string, type: 'verify' | 'reset', lockUntil: Date): Promise<void>;
  /**
   * Reset a flow's OTP attempt counter AND its lock in a single call — a
   * successful OTP verification always resets attempts and lock together.
   * Clears verifyLockUntil for type 'verify', resetLockUntil for type 'reset'.
   */
  resetOtpAttempts(id: string, type: 'verify' | 'reset'): Promise<void>;
}

export interface SessionAdapter {
  create(data: { userId: string; token: string; expiresAt: Date }): Promise<SessionRecord>;

  findValid(token: string): Promise<SessionRecord | null>;

  /**
   * Revoke a refresh token. MUST be a single atomic operation —
   * e.g. Mongoose: findOneAndUpdate({ token, isRevoked: false }, { isRevoked: true })
   *      Prisma:   updateMany({ where: { token, isRevoked: false }, data: { isRevoked: true } })
   *                then check the affected-row count
   *
   * Returns false if the token was ALREADY revoked when this call ran. The core
   * treats a false return as a reuse attack (someone used a token that had already
   * been used) and wipes every session for that user.
   *
   * A "find, then check, then save" implementation (two separate steps) reintroduces
   * a race condition: two concurrent refresh calls with the same stolen token can
   * both read isRevoked:false before either one writes, and both succeed. This is
   * not a hypothetical — it was a real bug in the original backend (see its audit,
   * finding S10), and it must not be reintroduced by any adapter.
   */
  revoke(token: string): Promise<boolean>;

  revokeAllForUser(userId: string): Promise<void>;
}

export interface AuthAdapter {
  users: UserAdapter;
  sessions: SessionAdapter;
}
