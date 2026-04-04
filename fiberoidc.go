package fiberoidc

import (
	"context"
	"errors"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/kncept/fiber-oidc/provider"
	"golang.org/x/oauth2"
)

type fiberOidcAuthLocalsKey struct{}

// direct access to fields, if you need to tweak or override something
// which should, of course, be entirely unnessesary
type FiberOidcStruct struct {
	Config        *Config
	OidcProviders *provider.OidcProviders
}

type FiberOidc interface {
	// Allows protection of a single route
	// Will redirect if required
	ProtectedRoute() fiber.Handler

	// Does not protect the route, but will still bind any valid
	// auth token to the request
	UnprotectedRoute() fiber.Handler

	// Handles the OIDC callback
	CallbackHandler() fiber.Handler

	// easy access to the callback path
	CallbackPath() string

	Providers() provider.Providers
}

func New(ctx context.Context, config *Config) (FiberOidc, error) {
	// ensure config is defaulted correctly
	config.WithDefaults()

	err := config.Validate()
	if err != nil {
		return nil, err
	}

	return &FiberOidcStruct{
		Config: config,
		OidcProviders: &provider.OidcProviders{
			OidcProviderConfig: config.OidcProviderConfig,
		},
	}, nil
}

func (obj *FiberOidcStruct) ProtectedRoute() fiber.Handler {
	return obj.handleProtectedRoute
}

func (obj *FiberOidcStruct) UnprotectedRoute() fiber.Handler {
	return obj.handleUnprotectedRoute
}

func (obj *FiberOidcStruct) CallbackHandler() fiber.Handler {
	return obj.handleOAuth2Callback
}

func (obj *FiberOidcStruct) CallbackPath() string {
	return obj.Config.CallbackPath
}

func (obj *FiberOidcStruct) Providers() provider.Providers {
	return obj.OidcProviders
}

func (obj *FiberOidcStruct) getAuthToken(c *fiber.Ctx) string {
	// Get authorization header
	auth := c.Get(fiber.HeaderAuthorization)
	if len(auth) > 7 && utils.EqualFold(auth[:7], "bearer ") {
		return auth[7:]
	}

	// if its empty, fallback to 'authcookiename' (if not blank)
	if auth == "" && obj.Config.AuthCookieName != "" {
		return c.Cookies(obj.Config.AuthCookieName)
	}
	return ""
}

func (obj *FiberOidcStruct) handleOAuth2Callback(c *fiber.Ctx) error {
	ctx := c.Context()

	//c.Query() doesn't seem to work.
	queries := c.Queries()
	state := queries["state"]
	code := queries["code"]

	oauth2Config, err := obj.OidcProviders.Oauth2Config(ctx)
	if err != nil {
		return err
	}
	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return err
	}

	// Extract the ID Token from OAuth2 token.
	rawToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return errors.New("auth code not exchangable for token")
	}

	userAuth, err := obj.OidcProviders.ValidateJwt(ctx, rawToken)
	if err != nil {
		return err
	}
	c.Locals(fiberOidcAuthLocalsKey{}, userAuth)

	// also set it into a cookie if configured to do so
	if obj.Config.AuthCookieName != "" {
		c.Cookie(&fiber.Cookie{
			Name:  obj.Config.AuthCookieName,
			Value: rawToken,
		})
	}
	// complete, use *FromContext to access user details
	return obj.Config.LoginSuccessHandler(state, c)
}

func (obj *FiberOidcStruct) doAuthRequiredRedirect(c *fiber.Ctx) error {
	state, err := obj.Config.LoginStateEncoder(c)
	if err != nil {
		return err
	}

	oauth2Config, err := obj.OidcProviders.Oauth2Config(c.Context())
	if err != nil {
		return err
	}

	// V3 Redirect (for later)
	// return c.Redirect().To(cfg.OidcConfig.AuthCodeURL(""))
	return c.Redirect(oauth2Config.AuthCodeURL(state), 302)
}

func (obj *FiberOidcStruct) handleProtectedRoute(c *fiber.Ctx) error {
	ctx := c.Context()
	rawToken := obj.getAuthToken(c)
	if rawToken == "" {
		return obj.doAuthRequiredRedirect(c)
	}

	userAuth, err := obj.OidcProviders.ValidateJwt(ctx, rawToken)
	if err != nil {
		if errors.Is(err, provider.ErrTokenExpired) {
			return obj.doAuthRequiredRedirect(c)
		}
		return err
	}
	c.Locals(fiberOidcAuthLocalsKey{}, userAuth)

	return c.Next()
}

func (obj *FiberOidcStruct) handleUnprotectedRoute(c *fiber.Ctx) error {
	ctx := c.Context()
	rawToken := obj.getAuthToken(c)
	if rawToken != "" {

		userAuth, err := obj.OidcProviders.ValidateJwt(ctx, rawToken)
		if err != nil {
			return err
		}
		c.Locals(fiberOidcAuthLocalsKey{}, userAuth)
	}
	return c.Next()
}

func ProviderAuth(c *fiber.Ctx) *provider.ProviderAuth {
	userAuth, ok := c.Locals(fiberOidcAuthLocalsKey{}).(*provider.ProviderAuth)
	if !ok {
		return nil
	}
	return userAuth
}

// GoOidcToken returns the jwt token found in the context
// returns a nil pointer if nothing exists
func GoOidcToken(c *fiber.Ctx) *gooidc.IDToken {
	userAuth := ProviderAuth(c)
	if userAuth != nil {
		return userAuth.GetIdToken()
	}
	return nil
}

func Oauth2Token(c *fiber.Ctx) *oauth2.Token {
	userAuth := ProviderAuth(c)
	if userAuth != nil {
		return userAuth.GetOauth2Token()
	}
	return nil
}

func Oauth2TokenSource(c *fiber.Ctx) oauth2.TokenSource {
	return &oauth2TokenSourceWrapper{
		c: c,
	}
}

type oauth2TokenSourceWrapper struct {
	c *fiber.Ctx
}

func (obj *oauth2TokenSourceWrapper) Token() (*oauth2.Token, error) {
	return Oauth2Token(obj.c), nil
}
