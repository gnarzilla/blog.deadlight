# scripts/gen-fed-keys.sh
#!/bin/bash

# Generate a random 64-character hex key
PRIVATE_KEY=$(openssl rand -hex 32)
PUBLIC_KEY=$PRIVATE_KEY  # For now, using symmetric key (upgrade to asymmetric later)

echo "Generated Federation Keys:"
echo ""
echo "Private Key (keep secret):"
echo "$PRIVATE_KEY"
echo ""
echo "Public Key (share with federation partners):"
echo "$PUBLIC_KEY"
echo ""
echo "To set in production:"
echo "  wrangler secret put FEDERATION_PRIVATE_KEY --remote"
echo "  (then paste the private key when prompted)"
echo ""
echo "To set in development (.dev.vars):"
echo "  FEDERATION_PRIVATE_KEY=\"$PRIVATE_KEY\""
