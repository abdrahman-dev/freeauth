import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';

// Shared lifecycle for integration tests that need a real MongoDB:
// one in-memory `mongod` per test FILE (beforeAll/afterAll), database wiped
// between tests (beforeEach) so the unique-email index never collides across
// tests. Models are registered on mongoose's default connection at import
// time (`src/internal/models/*`), which is exactly the connection used here.

let mongod: MongoMemoryServer | null = null;

export async function startMemoryMongo(): Promise<string> {
    mongod = await MongoMemoryServer.create();
    const uri = mongod.getUri();
    await mongoose.connect(uri);
    return uri;
}

export async function clearDatabase(): Promise<void> {
    const collections = mongoose.connection.collections;
    for (const collection of Object.values(collections)) {
        await collection.deleteMany({});
    }
}

export async function stopMemoryMongo(): Promise<void> {
    await mongoose.disconnect().catch(() => undefined);
    await mongod?.stop();
    mongod = null;
}
