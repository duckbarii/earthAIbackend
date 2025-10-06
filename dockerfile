# Use lightweight Node.js image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of your app
COPY . .

# Set environment variables
ENV NODE_ENV=production
ENV PORT=1100

# Expose your chosen port
EXPOSE 1100

# Start the Node.js server
CMD ["node", "server.js"]