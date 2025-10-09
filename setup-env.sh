#!/bin/bash

# Back to project root
cd "$(dirname "$0")"

echo "Setting up environment files..."

# Backend
if [ ! -f backend/.env ]; then
    echo "Creating backend/.env from .env.dev"
    cp backend/.env.dev backend/.env
    echo "Please review and edit backend/.env with your production settings"
else
    echo "backend/.env already exists, skipping"
fi

# Frontend
if [ ! -f droppy-ui/.env ]; then
    echo "Creating droppy-ui/.env from .env.development"
    cp droppy-ui/.env.development droppy-ui/.env
    echo "Please review and edit droppy-ui/.env with your production settings"
else
    echo "droppy-ui/.env already exists, skipping"
fi

echo ""
echo "Environment setup complete!"
echo "Please review the .env files and update them with your production settings."
echo "For production, you should generate a new SECRET_KEY and update it in backend/.env"
