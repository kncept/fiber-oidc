# Fiber OIDC

Fiber OIDC Middleware.

To install, 
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

	// fowrard for oidc login to: https://oidc.kncept.com/login
	app.Use(fiberoidc.New(fiberoidc.Config{
		OidcProvider:   oidcProvider,
		OidcConfig:     &oidcConfig,
		CallbackPath:   &redirectUrlPath, // I think? ==> if so, we can refactor to omit CallbackPath
		AuthCookieName: "user-token",
	}))
```

## OIDC Library Implementation

This middleware is built over https://github.com/coreos/go-oidc, which provides support for the https://pkg.go.dev/golang.org/x/oauth2 package
 
 The combination of a popular oidc solution, and the use of golang.org/x/oauth2 should mean that this middleware works for a variety of tools and use cases
 