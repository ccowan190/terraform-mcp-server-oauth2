#!/bin/bash

# Create OAuth2 credentials for Terraform MCP Server
# This script will help create the OAuth2 credentials needed for deployment

set -e

PROJECT_ID="hundredx-mcp"
SERVICE_NAME="terraform-mcp-server"
REGION="us-central1"

echo "🔧 Setting up OAuth2 credentials for Terraform MCP Server"
echo "Project: $PROJECT_ID"
echo

# Step 1: Check if user is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@hundredxinc.com"; then
    echo "❌ Please authenticate with a HundredX account first:"
    echo "   gcloud auth login"
    exit 1
fi

# Step 2: Set the project
gcloud config set project $PROJECT_ID

# Step 3: Get the service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region=$REGION --format="value(status.url)" 2>/dev/null || echo "https://terraform-mcp-server-7c3uq2gnva-uc.a.run.app")

echo "📍 Service URL: $SERVICE_URL"
echo

# Step 4: Create OAuth consent screen configuration
echo "🔐 Creating OAuth consent screen configuration..."

# Check if consent screen already exists
if gcloud alpha iap oauth-brands list --project=$PROJECT_ID --format="value(name)" 2>/dev/null | grep -q "projects/$PROJECT_ID"; then
    echo "✅ OAuth consent screen already exists"
else
    echo "⚠️  OAuth consent screen not found."
    echo "   Please create it manually in Google Cloud Console:"
    echo "   https://console.cloud.google.com/apis/credentials/consent?project=$PROJECT_ID"
    echo
    echo "   Configuration:"
    echo "   - User Type: Internal"
    echo "   - App name: Terraform MCP Server"
    echo "   - User support email: chris.cowan@hundredx.com"
    echo "   - Developer contact: chris.cowan@hundredx.com"
    echo "   - Scopes: email, profile, openid"
    echo
    read -p "Press Enter after creating the consent screen..."
fi

echo
echo "🆔 Creating OAuth2 Client ID..."
echo "   Go to: https://console.cloud.google.com/apis/credentials?project=$PROJECT_ID"
echo "   Click 'Create Credentials' → 'OAuth 2.0 Client ID'"
echo
echo "   Configuration:"
echo "   - Application type: Web application"
echo "   - Name: Terraform MCP Server for Claude.ai"
echo "   - Authorized JavaScript origins:"
echo "     - https://claude.ai"
echo "     - https://api.anthropic.com"
echo "     - $SERVICE_URL"
echo "   - Authorized redirect URIs:"
echo "     - https://claude.ai/oauth/callback"
echo "     - https://api.anthropic.com/oauth/callback"
echo "     - $SERVICE_URL/oauth/callback"
echo
echo "   After creating the OAuth2 client:"
echo "   1. Copy the Client ID"
echo "   2. Copy the Client Secret"
echo "   3. Set environment variables:"
echo "      export OAUTH2_CLIENT_ID=\"your-client-id\""
echo "      export OAUTH2_CLIENT_SECRET=\"your-client-secret\""
echo
echo "   Then run: ./deploy-oauth2.sh"
echo

# Step 5: Create sample environment file
cat > .env.oauth2 << EOF
# OAuth2 Configuration for Terraform MCP Server
# Copy your OAuth2 credentials here and source this file

# export OAUTH2_CLIENT_ID="your-client-id-here"
# export OAUTH2_CLIENT_SECRET="your-client-secret-here"

# Then run: source .env.oauth2 && ./deploy-oauth2.sh
EOF

echo "📝 Created .env.oauth2 template file"
echo "   Edit this file with your OAuth2 credentials"
echo "   Then run: source .env.oauth2 && ./deploy-oauth2.sh"
echo

echo "✅ OAuth2 setup preparation complete!"
echo "   Next steps:"
echo "   1. Create OAuth2 credentials in Google Cloud Console"
echo "   2. Edit .env.oauth2 with your credentials"
echo "   3. Run: source .env.oauth2 && ./deploy-oauth2.sh"
