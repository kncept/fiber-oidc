package fiberoidc

import (
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
)

// Config defines the config for middleware.
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	// Use this to determine Non-Authenticated routes, otherwise all routes
	// will be protected
	//
	// Optional. Default: nil
	Next func(c fiber.Ctx) bool

	OidcProvider gooidc.Provider
	OidcConfig   oauth2.Config
	CallbackPath *string // trigger oidc callback on this path

	AuthCookieName string // if set, also use an auth cookie (allow identity token to be set directly)

	// Authorizer defines a function you can pass
	// to check the credentials however you want.
	// It will be called with a username and password
	// and is expected to return true or false to indicate
	// that the credentials were approved or not.
	//
	// Optional. Default: nil.
	Authorizer func(gooidc.IDToken) bool

	// Unauthorized defines the response body for unauthorized responses.
	// By default it will return with a 401 Unauthorized and the correct WWW-Auth header
	//
	// Optional. Default: nil
	Unauthorized fiber.Handler
}

var configDefaultCallbackPath string = "/oidc/callback"

// ConfigDefault is the default config
var ConfigDefault = Config{
	Next: nil,
	Authorizer: func(token gooidc.IDToken) bool {
		return true
	},
	Unauthorized: func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderWWWAuthenticate, "Bearer")
		return c.SendStatus(fiber.StatusUnauthorized)
	},
	CallbackPath: &configDefaultCallbackPath,
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	cfg := Config{}
	if len(config) > 0 {
		cfg = config[0]
	}

	// Set default values
	if cfg.Next == nil {
		cfg.Next = ConfigDefault.Next
	}
	if cfg.Authorizer == nil {
		cfg.Authorizer = ConfigDefault.Authorizer
	}
	if cfg.Unauthorized == nil {
		cfg.Unauthorized = ConfigDefault.Unauthorized
	}
	if cfg.CallbackPath == nil {
		cfg.CallbackPath = ConfigDefault.CallbackPath
	}

	return cfg
}
