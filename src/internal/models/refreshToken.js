import mongoose from 'mongoose';

const refreshTokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user',
        required: true
    },

    token: {
        // Unique, matching the Prisma schema's `token String @unique`. The token
        // string is a session's identity, so two rows must never share one. The
        // random `jti` in every minted token (src/internal/authTokens.js) means
        // this never trips in practice; it is a defence-in-depth guarantee at the
        // storage layer. Deploys with autoIndex disabled must build this index
        // manually — see the deployment note in doc/backend.md.
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