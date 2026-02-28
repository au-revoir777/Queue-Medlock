FROM node:20-alpine
WORKDIR /app

# Copy only package files first for caching
COPY package.json package-lock.json ./

RUN apk add --no-cache curl

# Install dependencies
RUN npm install

# Copy the rest of your app
COPY . .

EXPOSE 9000
CMD ["npm", "start"]
