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
	ValidateJwt(ctx context.Context, jwt string, refreshToken string) (*ProviderAuth, error)

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

func (obj *OidcProviders) ValidateJwt(ctx context.Context, jwt string, refreshToken string) (*ProviderAuth, error) {
	if jwt == "" {
		return nil, ErrNoAuth
	}

	oauth2Token := &oauth2.Token{
		AccessToken:  jwt,
		RefreshToken: refreshToken,
	}

	idTokenVerifier, err := obj.IdTokenVerifier(ctx)
	if err != nil {
		return nil, errInitialization(err)
	}

	// Parse the JWT
	// token, err := jwt.Parse([]byte(tokenSring))
	idToken, err := idTokenVerifier.Verify(ctx, jwt)
	if err != nil {
		if tokenExpiredError, ok := err.(*gooidc.TokenExpiredError); ok {

			// auto-refresh doesn't seem to work with the oauth2Config thing
			// need to set up some more detailed tests
			if refreshToken != "" {
				oauth2Token.Expiry = tokenExpiredError.Expiry
				oauth2Config, err := obj.Oauth2Config(ctx)
				if err != nil {
					return nil, errInitialization(err)
				}

				oauth2Token, err = oauth2Config.TokenSource(ctx, oauth2Token).Token()
				if err != nil {
					return nil, err
				}

				// if the token changed, then we need the UPDATED refresh token (!!)
				if oauth2Token != nil && oauth2Token.AccessToken != jwt {
					jwt = oauth2Token.AccessToken

					idToken, err = idTokenVerifier.Verify(ctx, jwt)
					if err != nil {
						if _, ok := err.(*gooidc.TokenExpiredError); ok {
							err = EnsureErr(err, ErrTokenExpired)
						}
						return nil, err
					}
					// need to return this here
					// golang is funny with nested scopes and variable shading
					if err == nil && idToken != nil {
						oauth2Token.Expiry = idToken.Expiry // ensure this is copied in correctly
						return &ProviderAuth{
							Valid:       true,
							RawToken:    jwt,
							idToken:     idToken,
							oauth2Token: oauth2Token,
						}, nil
					}
				}
			} else {
				err = EnsureErr(err, ErrTokenExpired)
			}

		} else {
			return nil, EnsureErr(err, ErrNotAuthorized)
		}
	}

	if err == nil && idToken != nil {
		oauth2Token.Expiry = idToken.Expiry // ensure this is copied in correctly
		return &ProviderAuth{
			Valid:       true,
			RawToken:    jwt,
			idToken:     idToken,
			oauth2Token: oauth2Token,
		}, nil
	}

	return nil, ErrNotAuthorized

}
