# Stage 1: Build
ARG NODE_VERSION=24-alpine
FROM node:${NODE_VERSION} AS builder

# Create app directory
WORKDIR /workspace

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy source files and build
COPY . ./
RUN npm run build:server

# Stage 2: Runtime
FROM node:${NODE_VERSION}

# Create app directory
WORKDIR /workspace

# Copy config files
COPY server-config.json ./config.json

# Copy only the build output and production dependencies
COPY package*.json ./

RUN npm ci --omit=dev
COPY --from=builder /workspace/dist ./dist

# Set environment variables
ENV CONFIG_PATH=/workspace/config.json

# Set the entry point
ENTRYPOINT [ "node", "./dist/server.js" ]
