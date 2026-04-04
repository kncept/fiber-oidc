package provider

import (
	"context"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type providerAuthContextKey struct{}
type ProviderAuth struct {
	Valid       bool
	RawToken    string
	oauth2Token *oauth2.Token
	idToken     *gooidc.IDToken
}

func BindAuth(ctx context.Context, auth *ProviderAuth) context.Context {
	if auth != nil {
		return context.WithValue(ctx, providerAuthContextKey{}, auth)
	}
	return ctx
}
func GetAuth(ctx context.Context) *ProviderAuth {
	providerAuth := ctx.Value(providerAuthContextKey{})
	if providerAuth == nil {
		return nil
	}
	return providerAuth.(*ProviderAuth)
}

func (p *ProviderAuth) GetOauth2Token() *oauth2.Token {
	if p.oauth2Token == nil && p.idToken != nil {
		p.oauth2Token = &oauth2.Token{
			AccessToken: p.RawToken,
			Expiry:      p.idToken.Expiry,
		}
	}
	return p.oauth2Token
}

func (p *ProviderAuth) GetIdToken() *gooidc.IDToken {
	return p.idToken
}
