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
	return obj.protectedRouteHandler(true)
}

func (obj *FiberOidcStruct) UnprotectedRoute() fiber.Handler {
	return obj.protectedRouteHandler(false)
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
func (obj *FiberOidcStruct) getRefreshToken(c *fiber.Ctx) string {
	// Get authorization header
	refreshToken := c.Get("Authorization-Refresh") // shouldn't _really_ be sent.
	if refreshToken != "" {
		return refreshToken
	}

	// if its empty, fallback to 'refreshcookiename' (if not blank)
	if refreshToken == "" && obj.Config.AuthRefreshCookieName != "" {
		return c.Cookies(obj.Config.AuthRefreshCookieName)
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

	userAuth, err := obj.OidcProviders.ValidateJwt(ctx, oauth2Token.AccessToken, oauth2Token.RefreshToken)
	if err != nil {
		return err
	}
	c.Locals(fiberOidcAuthLocalsKey{}, userAuth)

	// also set it into a cookie if configured to do so
	if obj.Config.AuthCookieName != "" {
		c.Cookie(&fiber.Cookie{
			Name:  obj.Config.AuthCookieName,
			Value: oauth2Token.AccessToken,
		})
	}
	if obj.Config.AuthRefreshCookieName != "" {
		c.Cookie(&fiber.Cookie{
			Name:  obj.Config.AuthRefreshCookieName,
			Value: oauth2Token.RefreshToken,
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

func (obj *FiberOidcStruct) protectedRouteHandler(protectedRoute bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.Context()
		accessToken := obj.getAuthToken(c)
		refreshToken := ""
		if *obj.Config.AutoRefreshOnExpiry {
			refreshToken = obj.getRefreshToken(c)
		}
		if accessToken == "" {
			if protectedRoute {
				return obj.doAuthRequiredRedirect(c)
			} else {
				return c.Next()
			}
		}

		userAuth, err := obj.OidcProviders.ValidateJwt(ctx, accessToken, refreshToken)
		if protectedRoute && err != nil {
			if errors.Is(err, provider.ErrTokenExpired) {
				return obj.doAuthRequiredRedirect(c)
			}
			return err
		}
		if userAuth != nil {
			if userAuth.GetOauth2Token().AccessToken != accessToken && obj.Config.AuthCookieName != "" {
				c.Cookie(&fiber.Cookie{
					Name:  obj.Config.AuthCookieName,
					Value: userAuth.GetOauth2Token().AccessToken,
				})
			}
			if refreshToken != "" && userAuth.GetOauth2Token().RefreshToken != refreshToken && obj.Config.AuthRefreshCookieName != "" {
				c.Cookie(&fiber.Cookie{
					Name:  obj.Config.AuthRefreshCookieName,
					Value: userAuth.GetOauth2Token().RefreshToken,
				})
			}
			c.Locals(fiberOidcAuthLocalsKey{}, userAuth)
		} else {
			if obj.Config.AuthCookieName != "" {
				c.ClearCookie(obj.Config.AuthCookieName)
			}
			if obj.Config.AuthRefreshCookieName != "" {
				c.ClearCookie(obj.Config.AuthRefreshCookieName)
			}
		}

		return c.Next()
	}
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
