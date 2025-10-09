FROM node:18-alpine as build

WORKDIR /app

# Install dependencies
COPY droppy-ui/package*.json ./
RUN npm ci

# Copy project files and build
COPY droppy-ui/ .
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built assets from builder
COPY --from=build /app/dist /usr/share/nginx/html

# Copy nginx config
COPY compose/nginx/nginx.prod.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
