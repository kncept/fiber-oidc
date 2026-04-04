package provider

type OidcProviderConfig struct {
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
	// If set, limit the allowed signing args to this list
	// defaults to RS256,RS512
	SupportedSigningAlgs []string
}
