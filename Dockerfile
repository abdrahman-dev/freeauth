FROM node:22-bookworm-slim

WORKDIR /app

# Prisma's query engine needs OpenSSL on Debian slim images.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The test-only MongoDB binary download is not needed in the runtime image.
ENV MONGOMS_DISABLE_POSTINSTALL=1

# Used only by the root postinstall (prisma generate) during the build;
# ARG values are not retained as container environment variables.
ARG DATABASE_URL=postgresql://starkeep:starkeep@localhost:5432/starkeep

COPY . .

RUN npm ci \
    && npm run build \
    && npm cache clean --force

EXPOSE 3000

CMD ["npm", "start"]
