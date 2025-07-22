package fiberoidc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
)

// Config defines the config for middleware.
type Config struct {
	// REQUIRED
	Issuer string

	// REQUIRED
	ClientId string

	// REQUIRED
	ClientSecret string

	// FULLY QUALIFIED Oauth2 Callback path
	RedirectUri string

	// OPTIONAL, will be defaulted if unspecified
	Scopes []string

	// OPTIONAL
	// trigger oidc callback on this path.
	// It MUST match the RedirectUri value
	// If blank, this is default to the entire path from the RedirectUri
	CallbackPath string

	// OPTIONAL
	// if set, also use an auth cookie (allow identity token to be set directly)
	AuthCookieName string

	// OPTIONAL
	// Unauthorized defines the response body for unauthorized responses.
	// By default it will return with a 401 Unauthorized and the correct WWW-Auth header
	Unauthorized fiber.Handler

	// OPTIONAL
	// Called to serialize state for the OIDC redirect
	// If unspecified, will just the be the current path
	//
	// Should be paired with a SuccessHandler if provided
	LoginStateEncoder func(c *fiber.Ctx) (string, error)

	// OPTIONAL
	//
	// Called on login success to restore any application state there
	// may have been.
	// if unspecified, will assume that 'state' was the url path, and redirect there
	//
	// Should be paired with a StateEncoder if provided
	LoginSuccessHandler func(state string, c *fiber.Ctx) error

	// OPTIONAL
	// If set, limit the allowed signing args to this list
	// defaults to RS256,RS512
	SupportedSigningAlgs []string
}

// ConfigDefault is the default config
var configDefaults = Config{
	Unauthorized: func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderWWWAuthenticate, "Bearer")
		return c.SendStatus(fiber.StatusUnauthorized)
	},
	LoginStateEncoder: func(c *fiber.Ctx) (string, error) {
		return c.Path(), nil
	},
	LoginSuccessHandler: func(state string, c *fiber.Ctx) error {
		if state == "" {
			state = "/"
		}
		return c.Redirect(state, 302)
	},
	Scopes: []string{
		gooidc.ScopeOpenID, "email", "profile",
	},
	SupportedSigningAlgs: []string{
		"RS256",
		"RS512",
	},
}

// Helper function to set default values
func (cfg *Config) WithDefaults() *Config {
	if cfg == nil {
		cfg = &Config{}
	}

	if cfg.Unauthorized == nil {
		cfg.Unauthorized = configDefaults.Unauthorized
	}
	if cfg.RedirectUri != "" && cfg.CallbackPath == "" {
		// default to be the entire path in redirect url
		u, err := url.Parse(cfg.RedirectUri)
		if err == nil {
			cfg.CallbackPath = u.Path
		}
	}
	if cfg.LoginStateEncoder == nil {
		cfg.LoginStateEncoder = configDefaults.LoginStateEncoder
	}
	if cfg.LoginSuccessHandler == nil {
		cfg.LoginSuccessHandler = configDefaults.LoginSuccessHandler
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = configDefaults.Scopes
	}
	if len(cfg.SupportedSigningAlgs) == 0 {
		cfg.SupportedSigningAlgs = configDefaults.SupportedSigningAlgs
	}

	return cfg
}

func (obj *Config) Validate() error {
	validationErrors := make([]error, 0)

	if obj.Issuer == "" {
		validationErrors = append(validationErrors, errors.New("issuer must be specified"))
	}
	if obj.ClientId == "" {
		validationErrors = append(validationErrors, errors.New("client id must be specified"))
	}
	if obj.ClientSecret == "" {
		validationErrors = append(validationErrors, errors.New("client secret must be specified"))
	}
	if obj.RedirectUri == "" {
		validationErrors = append(validationErrors, errors.New("redirect uri must be specified"))
	}

	if obj.CallbackPath == "" {
		validationErrors = append(validationErrors, errors.New("callback path must be specified"))
	} else {
		if !strings.HasSuffix(obj.RedirectUri, obj.CallbackPath) {
			validationErrors = append(validationErrors, errors.New("callback path match redirect uri"))
		}
		if !strings.HasPrefix(obj.CallbackPath, "/") {
			validationErrors = append(validationErrors, fmt.Errorf("callback path must start with a slash: %v", obj.CallbackPath))
		}
	}

	if len(validationErrors) == 0 {
		return nil
	}
	return errors.Join(validationErrors...)
}
