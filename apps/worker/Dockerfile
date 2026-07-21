FROM node:22.17.0-bookworm-slim AS base
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable \
    && corepack prepare pnpm@10.34.5 --activate \
    && pnpm add --global turbo@2.10.5
WORKDIR /workspace

FROM base AS prune
COPY . .
RUN pnpm turbo prune @mergesignal/worker --docker

FROM base AS build
COPY --from=prune /workspace/out/json/ .
COPY --from=prune /workspace/out/pnpm-lock.yaml ./pnpm-lock.yaml
COPY --from=prune /workspace/tsconfig.base.json ./tsconfig.base.json
RUN pnpm install --frozen-lockfile
COPY --from=prune /workspace/out/full/ .
RUN pnpm turbo run build --filter=@mergesignal/worker... \
    && pnpm --filter @mergesignal/worker deploy --prod /runtime

FROM node:22.17.0-bookworm-slim AS runtime
ENV NODE_ENV=production
ENV WORKER_HEALTH_PORT=8080
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
USER node
WORKDIR /workspace
COPY --from=build --chown=node:node /runtime/ .
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.WORKER_HEALTH_PORT}/readyz`).then((response)=>{if(!response.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["node", "dist/main.js"]
