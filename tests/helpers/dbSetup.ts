import userModel from '../../src/internal/models/userModel.js';
import { hashOTP } from '../../src/internal/otpService.js';

// HTTP responses never reveal OTPs (they only go to the server log), so
// integration tests install a DETERMINISTIC OTP directly in the database and
// then exercise the real HTTP verify/reset endpoints with it. `hashOTP` is the
// exact function core uses, so the stored shape is faithful.
export const FIXED_OTP = '123456';

const TEN_MINUTES_MS = 10 * 60 * 1000;

export async function setVerifyOtp(email: string, otp: string = FIXED_OTP): Promise<void> {
    await userModel.findOneAndUpdate(
        { email },
        { verifyOTP: hashOTP(otp), verifyOTPExpire: Date.now() + TEN_MINUTES_MS }
    );
}

export async function setResetOtp(email: string, otp: string = FIXED_OTP): Promise<void> {
    await userModel.findOneAndUpdate(
        { email },
        { resetOTP: hashOTP(otp), resetOTPExpire: Date.now() + TEN_MINUTES_MS }
    );
}

export async function markAccountVerified(email: string): Promise<void> {
    await userModel.findOneAndUpdate({ email }, { isAccountVerified: true });
}
