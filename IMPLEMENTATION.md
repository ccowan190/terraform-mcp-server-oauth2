# Terraform MCP Server OAuth2 Implementation

## ✅ Status: Successfully Deployed

The Terraform MCP Server has been successfully modified to support OAuth2 authentication for Claude.ai integration.

## 🏗️ Architecture Overview

### Current Configuration
- **Service URL**: https://terraform-mcp-server-7c3uq2gnva-uc.a.run.app
- **Authentication**: IAM (fallback mode)
- **Health Check**: ✅ Working
- **Auth Status**: ✅ Working
- **MCP Endpoint**: ✅ Working

### OAuth2 Implementation Details

#### 1. **OAuth2 Handler** (`pkg/oauth2/oauth2.go`)
- **Google OAuth2 Integration**: Uses golang.org/x/oauth2 for Google authentication
- **HundredX Domain Validation**: Only allows @hundredxinc.com email addresses
- **Session Management**: Creates JWT-style tokens for authenticated sessions
- **Middleware Support**: HTTP middleware for protecting endpoints

#### 2. **Server Integration** (`cmd/terraform-mcp-server/main.go`)
- **Dual Authentication**: Falls back to IAM if OAuth2 not configured
- **OAuth2 Endpoints**: `/oauth/login` and `/oauth/callback`
- **Protected Endpoints**: MCP endpoints require authentication
- **Status Endpoints**: `/health` and `/auth/status` for monitoring

#### 3. **Environment Variables**
- `OAUTH2_CLIENT_ID`: Google OAuth2 Client ID
- `OAUTH2_CLIENT_SECRET`: Google OAuth2 Client Secret
- `OAUTH2_REDIRECT_URL`: OAuth2 callback URL (optional)

## 🔧 Configuration Options

### Mode 1: IAM Authentication (Current)
```bash
# Environment variables
MODE=http
TRANSPORT_PORT=8080

# No OAuth2 credentials configured
# Falls back to Cloud Run IAM authentication
```

### Mode 2: OAuth2 Authentication
```bash
# Environment variables
MODE=http
TRANSPORT_PORT=8080
OAUTH2_CLIENT_ID=your-google-client-id
OAUTH2_CLIENT_SECRET=your-google-client-secret
OAUTH2_REDIRECT_URL=https://terraform-mcp-server-7c3uq2gnva-uc.a.run.app/oauth/callback
```

## 🔐 OAuth2 Setup Process

### Step 1: Create Google OAuth2 Credentials
1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials?project=hundredx-mcp)
2. Create OAuth 2.0 Client ID with these settings:
   - **Type**: Web application
   - **Name**: Terraform MCP Server for Claude.ai
   - **Authorized origins**: 
     - `https://claude.ai`
     - `https://api.anthropic.com`
     - `https://terraform-mcp-server-7c3uq2gnva-uc.a.run.app`
   - **Redirect URIs**:
     - `https://claude.ai/oauth/callback`
     - `https://api.anthropic.com/oauth/callback`
     - `https://terraform-mcp-server-7c3uq2gnva-uc.a.run.app/oauth/callback`

### Step 2: Configure OAuth Consent Screen
1. Go to [OAuth Consent Screen](https://console.cloud.google.com/apis/credentials/consent?project=hundredx-mcp)
2. Choose "Internal" (HundredX organization only)
3. Configure:
   - **App name**: Terraform MCP Server
   - **User support email**: chris.cowan@hundredx.com
   - **Scopes**: email, profile, openid

### Step 3: Deploy with OAuth2
```bash
# Set environment variables
export OAUTH2_CLIENT_ID="your-client-id"
export OAUTH2_CLIENT_SECRET="your-client-secret"

# Deploy
./deploy-oauth2.sh
```

## 📋 API Endpoints

### Health Check
```bash
GET /health
Response: {
  "status": "ok",
  "service": "terraform-mcp-server",
  "transport": "streamable-http",
  "auth": "iam|oauth2"
}
```

### Authentication Status
```bash
GET /auth/status
Response: {
  "auth_type": "iam|oauth2",
  "auth_enabled": true,
  "login_url": "/oauth/login" | null
}
```

### OAuth2 Endpoints (when enabled)
```bash
GET /oauth/login        # Redirects to Google OAuth2
GET /oauth/callback     # Handles OAuth2 callback
```

### MCP Endpoint
```bash
POST /mcp              # Requires authentication
```

## 🎯 Claude.ai Integration

### Current Setup (IAM Mode)
- Use proxy method for immediate access
- Run: `gcloud run services proxy terraform-mcp-server --region=us-central1 --project=hundredx-mcp --port=8080`
- Configure Claude Desktop to use `http://localhost:8080/mcp`

### Future Setup (OAuth2 Mode)
1. Create OAuth2 credentials (Step 1-2 above)
2. Deploy with OAuth2 credentials (Step 3 above)
3. In Claude.ai integration settings:
   - **Service URL**: `https://terraform-mcp-server-7c3uq2gnva-uc.a.run.app/mcp`
   - **OAuth Client ID**: Your Google OAuth2 Client ID

## 🛡️ Security Features

- **Domain Validation**: Only @hundredxinc.com email addresses allowed
- **Token Expiration**: Session tokens expire after 1 hour
- **Secure Headers**: Proper HTTPS and security headers
- **IAM Fallback**: Maintains Cloud Run IAM security when OAuth2 not configured

## 📦 Files Created

1. **`pkg/oauth2/oauth2.go`** - OAuth2 authentication handler
2. **`deploy-oauth2.sh`** - Deployment script with OAuth2 support
3. **`test-oauth2.sh`** - OAuth2 functionality test suite
4. **`create-oauth2-credentials.sh`** - OAuth2 credentials setup guide
5. **`.env.oauth2`** - Environment variables template

## 🔄 Next Steps

1. **Create OAuth2 Credentials** in Google Cloud Console
2. **Test OAuth2 Flow** with created credentials
3. **Configure Claude.ai** with OAuth2 Client ID
4. **Remove IAM public access** once OAuth2 is working
5. **Monitor and validate** OAuth2 authentication

## 📞 Support

- **Contact**: chris.cowan@hundredx.com
- **Project**: hundredx-mcp
- **Service**: terraform-mcp-server
- **Region**: us-central1

## 🎉 Success Metrics

- ✅ OAuth2 handler implemented
- ✅ Server modified with OAuth2 support
- ✅ Successfully deployed to Cloud Run
- ✅ Health and status endpoints working
- ✅ MCP endpoint protected and functional
- ✅ Documentation and scripts created
- ⏳ OAuth2 credentials setup (pending manual step)
- ⏳ Claude.ai integration testing (pending OAuth2 setup)

The server is now ready for OAuth2 authentication once the Google OAuth2 credentials are configured!
