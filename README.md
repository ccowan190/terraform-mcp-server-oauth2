# Terraform MCP Server with OAuth2 Authentication

A HashiCorp Terraform MCP (Model Context Protocol) server enhanced with OAuth2 authentication support for seamless Claude.ai integration.

## 🚀 Features

- **OAuth2 Authentication**: Google OAuth2 integration for Claude.ai
- **Dual Authentication**: OAuth2 with Cloud Run IAM fallback
- **HundredX Integration**: Domain validation for @hundredxinc.com accounts
- **Claude.ai Ready**: Direct integration with Claude.ai remote MCP servers
- **Secure**: Session token management with expiration
- **Monitoring**: Health and authentication status endpoints

## 🏗️ Architecture

```
Claude.ai → OAuth2 Flow → Terraform MCP Server → Terraform Registry
                ↓
        Google Authentication
                ↓
        HundredX Domain Validation
```

## 📦 Installation

### Prerequisites
- Docker
- Google Cloud SDK (`gcloud`)
- Google Cloud project with OAuth2 credentials

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ccowan190/terraform-mcp-server-oauth2.git
   cd terraform-mcp-server-oauth2
   ```

2. **Set up OAuth2 credentials**:
   ```bash
   ./create-oauth2-credentials.sh
   ```

3. **Configure environment variables**:
   ```bash
   export OAUTH2_CLIENT_ID="your-google-client-id"
   export OAUTH2_CLIENT_SECRET="your-google-client-secret"
   ```

4. **Deploy to Google Cloud Run**:
   ```bash
   ./deploy-oauth2.sh
   ```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `OAUTH2_CLIENT_ID` | Google OAuth2 Client ID | Optional* |
| `OAUTH2_CLIENT_SECRET` | Google OAuth2 Client Secret | Optional* |
| `OAUTH2_REDIRECT_URL` | OAuth2 callback URL | Optional |
| `MODE` | Server mode (`http` or `stdio`) | No |
| `TRANSPORT_PORT` | HTTP server port | No |

*If not provided, server falls back to Cloud Run IAM authentication

### OAuth2 Setup

1. **Create OAuth2 Credentials** in [Google Cloud Console](https://console.cloud.google.com/apis/credentials):
   - Application type: Web application
   - Name: Terraform MCP Server for Claude.ai
   - Authorized origins: `https://claude.ai`, `https://api.anthropic.com`
   - Redirect URIs: `https://claude.ai/oauth/callback`, `https://api.anthropic.com/oauth/callback`

2. **Configure OAuth Consent Screen**:
   - User Type: Internal (for organization use)
   - App name: Terraform MCP Server
   - Scopes: email, profile, openid

## 🌐 API Endpoints

### Health Check
```http
GET /health
```
Response:
```json
{
  "status": "ok",
  "service": "terraform-mcp-server",
  "transport": "streamable-http",
  "auth": "oauth2|iam"
}
```

### Authentication Status
```http
GET /auth/status
```
Response:
```json
{
  "auth_type": "oauth2|iam",
  "auth_enabled": true,
  "login_url": "/oauth/login"
}
```

### OAuth2 Authentication (when enabled)
```http
GET /oauth/login          # Initiates OAuth2 flow
GET /oauth/callback       # Handles OAuth2 callback
```

### MCP Protocol
```http
POST /mcp                 # Terraform MCP operations (requires auth)
```

## 🔐 Claude.ai Integration

### Option 1: OAuth2 Authentication (Recommended)
1. Deploy with OAuth2 credentials configured
2. In Claude.ai integration settings:
   - **Service URL**: `https://your-service-url/mcp`
   - **OAuth Client ID**: Your Google OAuth2 Client ID

### Option 2: Proxy Method (Development)
```bash
# Start authenticated proxy
gcloud run services proxy terraform-mcp-server --region=us-central1 --project=your-project --port=8080

# Configure Claude Desktop
# URL: http://localhost:8080/mcp
```

## 🧪 Testing

Run the comprehensive test suite:
```bash
./test-oauth2.sh
```

Tests include:
- Health check endpoint
- Authentication status
- MCP endpoint protection
- OAuth2 flow (when enabled)

## 🛡️ Security Features

- **Domain Validation**: Only @hundredxinc.com email addresses allowed
- **Token Expiration**: Session tokens expire after 1 hour
- **HTTPS Only**: All OAuth2 flows use secure connections
- **IAM Fallback**: Cloud Run IAM security when OAuth2 not configured

## 📁 Project Structure

```
├── cmd/terraform-mcp-server/     # Main server code
│   ├── main.go                   # Server entry point with OAuth2 support
│   └── init.go                   # Initialization and configuration
├── pkg/oauth2/                   # OAuth2 authentication package
│   └── oauth2.go                 # OAuth2 handler implementation
├── deploy-oauth2.sh              # Deployment script
├── test-oauth2.sh                # Testing script
├── create-oauth2-credentials.sh  # OAuth2 setup guide
└── README.md                     # This file
```

## 🚀 Deployment

### Google Cloud Run
```bash
# Build and deploy
./deploy-oauth2.sh

# Or manually:
docker build -t gcr.io/your-project/terraform-mcp-server:oauth2 .
docker push gcr.io/your-project/terraform-mcp-server:oauth2
gcloud run deploy terraform-mcp-server \
  --image=gcr.io/your-project/terraform-mcp-server:oauth2 \
  --set-env-vars="OAUTH2_CLIENT_ID=your-id,OAUTH2_CLIENT_SECRET=your-secret"
```

### Local Development
```bash
# Run locally with OAuth2
docker run -p 8080:8080 \
  -e MODE=http \
  -e OAUTH2_CLIENT_ID=your-id \
  -e OAUTH2_CLIENT_SECRET=your-secret \
  terraform-mcp-server:oauth2
```

## 🔄 Authentication Modes

### OAuth2 Mode
- **Enabled**: When `OAUTH2_CLIENT_ID` and `OAUTH2_CLIENT_SECRET` are set
- **Flow**: Google OAuth2 → Domain validation → Session token
- **Claude.ai**: Direct integration with OAuth Client ID

### IAM Mode (Fallback)
- **Enabled**: When OAuth2 credentials are not configured
- **Flow**: Google Cloud IAM authentication
- **Claude.ai**: Requires proxy or service account

## 📊 Monitoring

Monitor your deployment:
```bash
# Check health
curl https://your-service-url/health

# Check auth status
curl https://your-service-url/auth/status

# View logs
gcloud run services logs read terraform-mcp-server --region=us-central1
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is based on HashiCorp's terraform-mcp-server and includes OAuth2 enhancements.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/ccowan190/terraform-mcp-server-oauth2/issues)
- **Documentation**: See `/docs` folder for detailed guides
- **Contact**: File an issue or reach out via GitHub

## 🎯 Roadmap

- [ ] JWT token signing for enhanced security
- [ ] Multiple OAuth2 provider support
- [ ] Advanced session management
- [ ] Audit logging
- [ ] Rate limiting
- [ ] Custom domain validation rules

---

Built with ❤️ for the Claude.ai and Terraform communities.
