#!/bin/sh

mkdir -p compose/nginx/ssl

# Generate a self-signed certificate for local development
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout compose/nginx/ssl/droppy.key \
  -out compose/nginx/ssl/droppy.crt \
  -subj "/CN=droppy.local" \
  -addext "subjectAltName=DNS:droppy.local"

echo "\nSSL certificate generated in compose/nginx/ssl/"
echo "Add the following to your /etc/hosts file if not already present:"
echo "127.0.0.1    droppy.local"
echo "\nTo trust the certificate on your local machine, you may need to import it to your system's trust store."
