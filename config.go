package fiberoidc

import (
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
)

// Defines a function to skip this middleware when returning false.
// Use this to determine Authenticated and Non-Authenticated routes
type RouteProtectorFunc func(c *fiber.Ctx) (bool, error)

// Config defines the config for middleware.
type Config struct {
	Issuer       string
	ClientId     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string

	// // a configured coreos/go-oidc to authenticate against
	// OidcProvider *gooidc.Provider
	// // Configuration for your oauth2 provider
	// OidcConfig *oauth2.Config

	// trigger oidc callback on this path.
	// It should match the path from the OidcConfig value.
	// N.B. this is defaulted to the configDefaultCallbackPath (/oidc/callback) if not specified
	CallbackPath *string

	// Optional
	//
	// if set, also use an auth cookie (allow identity token to be set directly)
	AuthCookieName string

	// Optional
	//
	// Unauthorized defines the response body for unauthorized responses.
	// By default it will return with a 401 Unauthorized and the correct WWW-Auth header
	Unauthorized fiber.Handler

	// Optional
	//
	// Called to serialize state for the OIDC redirect
	// If unspecified, will just the be the current path
	//
	// Should be paired with a SuccessHandler if provided
	StateEncoder func(c *fiber.Ctx) (string, error)
	// Optional
	//
	// Called on login success to restore any application state there
	// may have been.
	// if unspecified, will assume that 'state' was the url path, and redirect there
	//
	// Should be paired with a StateEncoder if provided
	SuccessHandler func(state string, c *fiber.Ctx) error
}

var configDefaultCallbackPath string = "/oidc/callback"

// ClientID:     os.Getenv("OIDC_CLIENT_ID"),
// ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
// Endpoint:     oidcProvider.Endpoint(),
// RedirectURL:  fmt.Sprintf("http://localhost:3000%v", redirectUrlPath),
// Scopes: []string{
// 	gooidc.ScopeOpenID, "email", "profile",
// },

// ConfigDefault is the default config
var ConfigDefault = Config{
	Unauthorized: func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderWWWAuthenticate, "Bearer")
		return c.SendStatus(fiber.StatusUnauthorized)
	},
	CallbackPath: &configDefaultCallbackPath,
	StateEncoder: func(c *fiber.Ctx) (string, error) {
		return c.Path(), nil
	},
	SuccessHandler: func(state string, c *fiber.Ctx) error {
		return c.Redirect(state, 302)
	},
	Scopes: []string{
		gooidc.ScopeOpenID, "email", "profile",
	},
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	cfg := Config{}
	if len(config) > 0 {
		cfg = config[0]
	}

	// Set default values
	if cfg.Unauthorized == nil {
		cfg.Unauthorized = ConfigDefault.Unauthorized
	}
	if cfg.CallbackPath == nil {
		cfg.CallbackPath = ConfigDefault.CallbackPath
	}
	if cfg.StateEncoder == nil {
		cfg.StateEncoder = ConfigDefault.StateEncoder
	}
	if cfg.SuccessHandler == nil {
		cfg.SuccessHandler = ConfigDefault.SuccessHandler
	}
	if cfg.Scopes == nil || len(cfg.Scopes) == 0 {
		cfg.Scopes = ConfigDefault.Scopes
	}

	return cfg
}
