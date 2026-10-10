import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {type: String, required: true},
    email: {type: String, required: true, unique: true},
    password: {type: String, required: false, default: null},
    // 'local' for password users (default, covers all pre-existing records);
    // 'google'/'github' for OAuth-only users created via createOAuthUser (no password set).
    provider: {type: String, enum: ['local', 'google', 'github'], default: 'local'},
    providerId: {type: String, default: null},
    verifyOTP: {type: String, default: null},
    verifyOTPExpire: {type: Number, default: 0},
    isAccountVerified: {type: Boolean, default: false},
    resetOTP: {type: String, default: null},
    resetOTPExpire: {type: Number, default: 0},
    verifyAttempts: {type: Number, default: 0},
    verifyLockUntil: {type: Date, default: null},
    resetAttempts: {type: Number, default: 0},
    resetLockUntil: {type: Date, default: null}
})

const userModel = mongoose.model("user", userSchema);

export default userModel;
