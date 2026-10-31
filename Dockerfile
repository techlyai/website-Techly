FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=80
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server.js ./
COPY scripts ./scripts
COPY public ./public
EXPOSE 80
USER node
CMD ["node", "server.js"]
