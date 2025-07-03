#!/bin/bash

# Deploy Terraform MCP Server with OAuth2 support to Google Cloud Run
# Project: hundredx-mcp

set -e

PROJECT_ID="hundredx-mcp"
SERVICE_NAME="terraform-mcp-server"
REGION="us-central1"
SERVICE_ACCOUNT="terraform-mcp-server@${PROJECT_ID}.iam.gserviceaccount.com"

echo "🚀 Deploying Terraform MCP Server with OAuth2 support"
echo "Project: $PROJECT_ID"
echo "Service: $SERVICE_NAME"
echo "Region: $REGION"
echo

# Check if OAuth2 credentials are set
if [[ -z "$OAUTH2_CLIENT_ID" || -z "$OAUTH2_CLIENT_SECRET" ]]; then
    echo "⚠️  OAuth2 credentials not set. Server will fall back to IAM authentication."
    echo "   To enable OAuth2, set OAUTH2_CLIENT_ID and OAUTH2_CLIENT_SECRET environment variables."
    echo "   Or create them in Google Cloud Console and set them before running this script."
    echo
    echo "   Example:"
    echo "   export OAUTH2_CLIENT_ID=\"your-client-id\""
    echo "   export OAUTH2_CLIENT_SECRET=\"your-client-secret\""
    echo
    read -p "Continue without OAuth2? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Deployment cancelled."
        exit 1
    fi
fi

# Set project
gcloud config set project $PROJECT_ID

# Build and deploy
echo "🔨 Building and deploying to Cloud Run..."

# Get current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Build the Docker image
echo "📦 Building Docker image..."
docker build -t gcr.io/$PROJECT_ID/$SERVICE_NAME:oauth2-enabled .

# Push to Google Container Registry
echo "📤 Pushing to Google Container Registry..."
docker push gcr.io/$PROJECT_ID/$SERVICE_NAME:oauth2-enabled

# Deploy to Cloud Run with OAuth2 environment variables
echo "🚀 Deploying to Cloud Run..."
if [[ -n "$OAUTH2_CLIENT_ID" && -n "$OAUTH2_CLIENT_SECRET" ]]; then
    # Deploy with OAuth2 credentials
    gcloud run deploy $SERVICE_NAME \
        --image=gcr.io/$PROJECT_ID/$SERVICE_NAME:oauth2-enabled \
        --region=$REGION \
        --platform=managed \
        --memory=512Mi \
        --cpu=1 \
        --max-instances=10 \
        --port=8080 \
        --set-env-vars="MODE=http,TRANSPORT_PORT=8080,OAUTH2_CLIENT_ID=$OAUTH2_CLIENT_ID,OAUTH2_CLIENT_SECRET=$OAUTH2_CLIENT_SECRET,OAUTH2_REDIRECT_URL=https://terraform-mcp-server-7c3uq2gnva-uc.a.run.app/oauth/callback" \
        --service-account=$SERVICE_ACCOUNT \
        --allow-unauthenticated
    
    echo "✅ OAuth2 authentication enabled"
else
    # Deploy without OAuth2 (IAM only)
    gcloud run deploy $SERVICE_NAME \
        --image=gcr.io/$PROJECT_ID/$SERVICE_NAME:oauth2-enabled \
        --region=$REGION \
        --platform=managed \
        --memory=512Mi \
        --cpu=1 \
        --max-instances=10 \
        --port=8080 \
        --set-env-vars="MODE=http,TRANSPORT_PORT=8080" \
        --service-account=$SERVICE_ACCOUNT \
        --no-allow-unauthenticated
    
    echo "✅ IAM authentication enabled (OAuth2 not configured)"
fi

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region=$REGION --format="value(status.url)")

echo
echo "🎉 Deployment completed successfully!"
echo "📍 Service URL: $SERVICE_URL"
echo "🏥 Health check: $SERVICE_URL/health"
echo "🔐 Auth status: $SERVICE_URL/auth/status"
echo

if [[ -n "$OAUTH2_CLIENT_ID" && -n "$OAUTH2_CLIENT_SECRET" ]]; then
    echo "🔑 OAuth2 Endpoints:"
    echo "   Login: $SERVICE_URL/oauth/login"
    echo "   Callback: $SERVICE_URL/oauth/callback"
    echo
    echo "📋 For Claude.ai integration:"
    echo "   - Add OAuth Client ID: $OAUTH2_CLIENT_ID"
    echo "   - Service URL: $SERVICE_URL/mcp"
    echo
else
    echo "🔧 To enable OAuth2 authentication:"
    echo "   1. Create OAuth2 credentials in Google Cloud Console"
    echo "   2. Set environment variables and redeploy:"
    echo "      export OAUTH2_CLIENT_ID=\"your-client-id\""
    echo "      export OAUTH2_CLIENT_SECRET=\"your-client-secret\""
    echo "      ./deploy-oauth2.sh"
    echo
fi

echo "✅ Ready for use!"
