FROM node:24-bookworm-slim
WORKDIR /opt/onelayer
COPY packages/canonical-ts/src packages/canonical-ts/src
COPY packages/merkle-ts/src packages/merkle-ts/src
COPY packages/snapshot-ts/src packages/snapshot-ts/src
ENTRYPOINT ["node", "packages/snapshot-ts/src/cli.ts"]
