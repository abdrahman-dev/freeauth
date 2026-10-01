import mongoose from 'mongoose';

const refreshTokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user',
        required: true
    },

    token: {
        // Unique, matching the Prisma schema's `token String @unique`: the token
        // string is a session's identity, so two rows must never share one. With the
        // random jti in every token this never trips in practice; it is a defence-in-
        // depth guarantee at the storage layer against duplicate-token rows.
        type: String,
        required: true,
        unique: true
    },

    expiresAt: {
        type: Date,
        required: true,
        index: { expires: '0'}
    },

    isRevoked: {
        type: Boolean,
        default: false
    },
    
}, {
    timestamps: true
});

const refreshTokenModel = mongoose.model('RefreshToken', refreshTokenSchema);

export default refreshTokenModel;