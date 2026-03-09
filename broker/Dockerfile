FROM node:20-alpine
WORKDIR /app

COPY broker/package.json broker/package-lock.json ./
RUN apk add --no-cache curl
RUN npm install

COPY broker/src/ ./src/

EXPOSE 9000
CMD ["node", "src/index.js"]
