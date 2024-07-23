# Fiber OIDC

Fiber OIDC Middleware.<br>
Yes, it's quite a lot chunkier than fiber, but it does provide an easy way to integrate OIDC into your app.

# Quickstart

To install:
`go get github.com/kncept/fiber-oidc`

Example snippet from another app:
```
oidcProvider, err := gooidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err != nil {
		panic(err)
	}

	redirectUrlPath := "/oidc/callback"
	oidcConfig := oauth2.Config{
		ClientID:     os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  fmt.Sprintf("http://localhost:3000%v", redirectUrlPath),
		Scopes: []string{
			gooidc.ScopeOpenID, "email", "profile",
		},
	}

	app.Use(fiberoidc.New(fiberoidc.Config{
		OidcProvider:   oidcProvider,
		OidcConfig:     &oidcConfig,
		CallbackPath:   &redirectUrlPath, // I think? ==> if so, we can refactor to omit CallbackPath
		AuthCookieName: "user-token",
	}))
```

You can access the id token in your handler by doing this: `idToken := fiberoidc.IdTokenFromContext(c)`

## OIDC Library Implementation

This middleware is built over https://github.com/coreos/go-oidc, which provides support for the https://pkg.go.dev/golang.org/x/oauth2 package.

 ## Handling extra claims
 Use a struct something like this:
 ```
 type OidcClaims struct {
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`

	Name string `json:"name,omitempty"`

	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`

	PoneNumber          string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`
}
```
with the following code snippet in your handler:
```
	idToken := fiberoidc.IdTokenFromContext(c)
    claims := &OidcClaims{}
    err = idToken.Claims(&claims)
```
