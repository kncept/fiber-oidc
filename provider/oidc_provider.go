package provider

import (
	"context"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Providers interface {
	// FiberOidc uses lazy initialization - call this if you're eager!
	Initialize(ctx context.Context) error

	// validate an inbound auth
	// N.B. this does NOT bind ProviderAuth to a context on success
	ValidateJwt(ctx context.Context, jwt string) (*ProviderAuth, error)

	// individual provider components
	GoOidcProvider(ctx context.Context) (*gooidc.Provider, error)
	Oauth2Config(ctx context.Context) (*oauth2.Config, error)
	IdTokenVerifier(ctx context.Context) (*gooidc.IDTokenVerifier, error)
}

type OidcProviders struct {
	OidcProviderConfig OidcProviderConfig
	oauth2Config       *oauth2.Config
	goOidcProvider     *gooidc.Provider
	idTokenVerifier    *gooidc.IDTokenVerifier
}

func (obj *OidcProviders) Initialize(ctx context.Context) error {
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

func (obj *OidcProviders) GoOidcProvider(ctx context.Context) (*gooidc.Provider, error) {
	if obj.goOidcProvider == nil {
		config := obj.OidcProviderConfig
		oidcProvider, err := gooidc.NewProvider(ctx, config.Issuer)
		if err != nil {
			return nil, errInitialization(err)
		}
		obj.goOidcProvider = oidcProvider
	}
	return obj.goOidcProvider, nil
}

func (obj *OidcProviders) Oauth2Config(ctx context.Context) (*oauth2.Config, error) {
	if obj.oauth2Config == nil {
		goOidcProvider, err := obj.GoOidcProvider(ctx)
		if err != nil {
			return nil, errInitialization(err)
		}
		config := obj.OidcProviderConfig
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

func (obj *OidcProviders) IdTokenVerifier(ctx context.Context) (*gooidc.IDTokenVerifier, error) {
	if obj.idTokenVerifier == nil {
		goOidcProvider, err := obj.GoOidcProvider(ctx)
		if err != nil {
			return nil, errInitialization(err)
		}
		config := obj.OidcProviderConfig

		// cache id token verifier
		idTokenVerifier := goOidcProvider.Verifier(&gooidc.Config{
			ClientID:             config.ClientId,
			SupportedSigningAlgs: config.SupportedSigningAlgs,
		})
		obj.idTokenVerifier = idTokenVerifier
	}
	return obj.idTokenVerifier, nil
}

func (obj *OidcProviders) ValidateJwt(ctx context.Context, jwt string) (*ProviderAuth, error) {
	if jwt == "" {
		return nil, ErrNoAuth
	}

	idTokenVerifier, err := obj.IdTokenVerifier(ctx)
	if err != nil {
		return nil, errInitialization(err)
	}

	// Parse the JWT
	// token, err := jwt.Parse([]byte(tokenSring))
	idToken, err := idTokenVerifier.Verify(ctx, jwt)
	if err != nil {
		if _, ok := err.(*gooidc.TokenExpiredError); ok {
			err = ensure(err, ErrTokenExpired) // transform type - suitable for use with errors.Is()
		}
		return nil, ensure(err, ErrNotAuthorized)
	}
	if err == nil && idToken != nil {
		return &ProviderAuth{
			Valid:    true,
			RawToken: jwt,
			idToken:  idToken,
		}, nil
	}

	return nil, ErrNotAuthorized

}
