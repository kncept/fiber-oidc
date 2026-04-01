package fiberoidc

import (
	"context"
	"errors"
	"sync"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"golang.org/x/oauth2"
)

// internal context key for the oidc
type goOidcTokenKey struct{}
type oauth2TokenKey struct{}

// direct access to fields, if you need to tweak or override something
// which should, of course, be entirely unnessesary
type FiberOidcStruct struct {
	Config *Config

	oauth2Config_mu    sync.Mutex
	oauth2Config       *oauth2.Config
	goOidcProvider_mu  sync.Mutex
	goOidcProvider     *gooidc.Provider
	idTokenVerifier_mu sync.Mutex
	idTokenVerifier    *gooidc.IDTokenVerifier
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

	// FiberOidc uses lazy initialization - call this if you're eager!
	Initialize(ctx context.Context) error

	Providers() Providers
}

type Providers interface {
	GoOidcProvider(ctx context.Context) (*gooidc.Provider, error)
	Oauth2Config(ctx context.Context) (*oauth2.Config, error)
	IdTokenVerifier(ctx context.Context) (*gooidc.IDTokenVerifier, error)
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
	}, nil
}

func (obj *FiberOidcStruct) GoOidcProvider(ctx context.Context) (*gooidc.Provider, error) {
	obj.goOidcProvider_mu.Lock()
	defer obj.goOidcProvider_mu.Unlock()
	if obj.goOidcProvider == nil {
		config := obj.Config
		oidcProvider, err := gooidc.NewProvider(ctx, config.Issuer)
		if err != nil {
			return nil, err
		}
		obj.goOidcProvider = oidcProvider
	}
	return obj.goOidcProvider, nil
}

func (obj *FiberOidcStruct) Oauth2Config(ctx context.Context) (*oauth2.Config, error) {
	obj.oauth2Config_mu.Lock()
	defer obj.oauth2Config_mu.Unlock()
	if obj.oauth2Config == nil {
		goOidcProvider, err := obj.GoOidcProvider(ctx)
		if err != nil {
			return nil, err
		}
		config := obj.Config
		obj.oauth2Config = &oauth2.Config{
			ClientID:     config.ClientId,
			ClientSecret: config.ClientSecret,
			Endpoint:     goOidcProvider.Endpoint(),
			RedirectURL:  config.RedirectUri,
			Scopes:       config.Scopes,
		}
	}
	return obj.oauth2Config, nil
}

func (obj *FiberOidcStruct) IdTokenVerifier(ctx context.Context) (*gooidc.IDTokenVerifier, error) {
	obj.idTokenVerifier_mu.Lock()
	obj.idTokenVerifier_mu.Unlock()
	if obj.idTokenVerifier == nil {
		goOidcProvider, err := obj.GoOidcProvider(ctx)
		if err != nil {
			return nil, err
		}
		config := obj.Config

		// cache id token verifier
		idTokenVerifier := goOidcProvider.Verifier(&gooidc.Config{
			ClientID:             config.ClientId,
			SupportedSigningAlgs: config.SupportedSigningAlgs,
		})
		obj.idTokenVerifier = idTokenVerifier
	}
	return obj.idTokenVerifier, nil
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

func (obj *FiberOidcStruct) Initialize(ctx context.Context) error {
	_, err := obj.GoOidcProvider(ctx)
	if err != nil {
		return err
	}
	_, err = obj.Oauth2Config(ctx)
	if err != nil {
		return err
	}
	_, err = obj.IdTokenVerifier(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (obj *FiberOidcStruct) Providers() Providers {
	return obj
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

	oauth2Config, err := obj.Oauth2Config(ctx)
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

	idTokenVerifier, err := obj.IdTokenVerifier(ctx)
	if err != nil {
		return err
	}

	// Parse and verify ID Token payload.
	idToken, err := idTokenVerifier.Verify(ctx, rawToken)
	if err != nil {
		return err
	}
	// if successful, bind to context
	c.Locals(goOidcTokenKey{}, idToken)
	c.Locals(oauth2TokenKey{}, oauth2Token)

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

	oauth2Config, err := obj.Oauth2Config(c.Context())
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

	idTokenVerifier, err := obj.IdTokenVerifier(ctx)
	if err != nil {
		return err
	}

	// Parse the JWT
	// token, err := jwt.Parse([]byte(tokenSring))
	idToken, err := idTokenVerifier.Verify(ctx, rawToken)
	if err != nil {
		// handle expired by re-asking for auth
		if _, ok := err.(*gooidc.TokenExpiredError); ok {
			return obj.doAuthRequiredRedirect(c)
		}
		return obj.Config.Unauthorized(c)
	}
	if idToken == nil {
		return obj.Config.Unauthorized(c)
	}
	// if successful, bind to context
	oauth2Token := &oauth2.Token{
		AccessToken: rawToken,
		Expiry:      idToken.Expiry,
	}
	c.Locals(goOidcTokenKey{}, idToken)
	c.Locals(oauth2TokenKey{}, oauth2Token)
	return c.Next()
}

func (obj *FiberOidcStruct) handleUnprotectedRoute(c *fiber.Ctx) error {
	ctx := c.Context()
	rawToken := obj.getAuthToken(c)
	if rawToken != "" {
		idTokenVerifier, err := obj.IdTokenVerifier(ctx)
		if err != nil {
			return err
		}

		// Parse the JWT
		// token, err := jwt.Parse([]byte(tokenSring))
		idToken, err := idTokenVerifier.Verify(ctx, rawToken)
		if err == nil && idToken != nil {
			// if successful, bind to context
			oauth2Token := &oauth2.Token{
				AccessToken: rawToken,
				Expiry:      idToken.Expiry,
			}
			c.Locals(goOidcTokenKey{}, idToken)
			c.Locals(oauth2TokenKey{}, oauth2Token)
		}

	}
	return c.Next()
}

// GoOidcToken returns the jwt token found in the context
// returns a nil pointer if nothing exists
func GoOidcToken(c *fiber.Ctx) *gooidc.IDToken {
	token, ok := c.Locals(goOidcTokenKey{}).(*gooidc.IDToken)
	if !ok {
		return nil
	}
	return token
}

func Oauth2Token(c *fiber.Ctx) *oauth2.Token {
	token, ok := c.Locals(oauth2TokenKey{}).(*oauth2.Token)
	if !ok {
		return nil
	}
	return token
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
