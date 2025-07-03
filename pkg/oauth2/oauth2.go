// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// OAuth2Config holds OAuth2 configuration
type OAuth2Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	TokenURL     string
	AuthURL      string
	logger       *log.Logger
}

// OAuth2Handler handles OAuth2 authentication
type OAuth2Handler struct {
	config *OAuth2Config
	oauth2Config *oauth2.Config
	logger *log.Logger
}

// NewOAuth2Handler creates a new OAuth2 handler
func NewOAuth2Handler(logger *log.Logger) (*OAuth2Handler, error) {
	clientID := os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH2_CLIENT_SECRET")
	redirectURL := os.Getenv("OAUTH2_REDIRECT_URL")
	
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("OAuth2 credentials not configured. Set OAUTH2_CLIENT_ID and OAUTH2_CLIENT_SECRET environment variables")
	}
	
	if redirectURL == "" {
		// Default redirect URL for Cloud Run
		redirectURL = "https://terraform-mcp-server-7c3uq2gnva-uc.a.run.app/oauth/callback"
	}

	config := &OAuth2Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		TokenURL:     "https://oauth2.googleapis.com/token",
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		logger:       logger,
	}

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthURL,
			TokenURL: config.TokenURL,
		},
	}

	return &OAuth2Handler{
		config:       config,
		oauth2Config: oauth2Config,
		logger:       logger,
	}, nil
}

// generateState generates a random state string for OAuth2 security
func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// HandleAuth handles the OAuth2 authorization request
func (h *OAuth2Handler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	
	// Store state in session or cache (for production, use Redis or similar)
	// For now, we'll include it in the URL and validate it in the callback
	
	url := h.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	
	h.logger.Infof("Redirecting to OAuth2 provider: %s", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleCallback handles the OAuth2 callback
func (h *OAuth2Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	
	if code == "" {
		h.logger.Error("No code in OAuth2 callback")
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}
	
	if state == "" {
		h.logger.Error("No state in OAuth2 callback")
		http.Error(w, "No state provided", http.StatusBadRequest)
		return
	}
	
	// Exchange code for token
	token, err := h.oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		h.logger.Errorf("Failed to exchange code for token: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}
	
	// Get user info
	userInfo, err := h.getUserInfo(token.AccessToken)
	if err != nil {
		h.logger.Errorf("Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	
	// Validate user domain (HundredX only)
	if !strings.HasSuffix(userInfo.Email, "@hundredxinc.com") {
		h.logger.Errorf("Unauthorized domain: %s", userInfo.Email)
		http.Error(w, "Unauthorized domain", http.StatusForbidden)
		return
	}
	
	// Create JWT token or session token for the user
	sessionToken, err := h.createSessionToken(userInfo)
	if err != nil {
		h.logger.Errorf("Failed to create session token: %v", err)
		http.Error(w, "Failed to create session token", http.StatusInternalServerError)
		return
	}
	
	// Return success response with token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": sessionToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"user":         userInfo,
	})
}

// UserInfo represents user information from OAuth2 provider
type UserInfo struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Picture  string `json:"picture"`
	Verified bool   `json:"verified_email"`
}

// getUserInfo gets user information from the OAuth2 provider
func (h *OAuth2Handler) getUserInfo(accessToken string) (*UserInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+accessToken)
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: %s", resp.Status)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}
	
	return &userInfo, nil
}

// createSessionToken creates a session token for the user
func (h *OAuth2Handler) createSessionToken(userInfo *UserInfo) (string, error) {
	// For production, use proper JWT tokens with signing
	// For now, create a simple encoded token
	tokenData := map[string]interface{}{
		"email":     userInfo.Email,
		"name":      userInfo.Name,
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	
	tokenBytes, err := json.Marshal(tokenData)
	if err != nil {
		return "", err
	}
	
	// Base64 encode the token (in production, use proper JWT signing)
	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

// ValidateToken validates an access token
func (h *OAuth2Handler) ValidateToken(token string) (*UserInfo, error) {
	// Decode the token
	tokenBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token format")
	}
	
	var tokenData map[string]interface{}
	if err := json.Unmarshal(tokenBytes, &tokenData); err != nil {
		return nil, fmt.Errorf("invalid token data")
	}
	
	// Check expiration
	if exp, ok := tokenData["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("token expired")
		}
	}
	
	// Extract user info
	email, _ := tokenData["email"].(string)
	name, _ := tokenData["name"].(string)
	
	return &UserInfo{
		Email: email,
		Name:  name,
	}, nil
}

// AuthMiddleware is HTTP middleware for OAuth2 authentication
func (h *OAuth2Handler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for OAuth2 endpoints
		if strings.HasPrefix(r.URL.Path, "/oauth/") || r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		
		// Check for Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.logger.Debug("No authorization header found")
			h.sendAuthChallenge(w, r)
			return
		}
		
		// Extract token from "Bearer <token>" format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			h.logger.Debug("Invalid authorization header format")
			h.sendAuthChallenge(w, r)
			return
		}
		
		token := parts[1]
		
		// Validate token
		userInfo, err := h.ValidateToken(token)
		if err != nil {
			h.logger.Debugf("Token validation failed: %v", err)
			h.sendAuthChallenge(w, r)
			return
		}
		
		// Add user info to request context
		ctx := context.WithValue(r.Context(), "user", userInfo)
		r = r.WithContext(ctx)
		
		h.logger.Debugf("Authenticated user: %s", userInfo.Email)
		next.ServeHTTP(w, r)
	})
}

// sendAuthChallenge sends an authentication challenge
func (h *OAuth2Handler) sendAuthChallenge(w http.ResponseWriter, r *http.Request) {
	// For web browsers, redirect to OAuth2 authorization
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		h.HandleAuth(w, r)
		return
	}
	
	// For API clients, return JSON with authorization URL
	state := generateState()
	authURL := h.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":             "authentication_required",
		"authorization_url": authURL,
		"message":          "Please authenticate using the provided authorization URL",
	})
}
