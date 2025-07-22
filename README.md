# Fiber OIDC

Fiber OIDC Middleware.<br>
Yes, it's quite a lot chunkier than fiber, but it does provide an easy way to integrate OIDC into your app.<br>

N.B. It does things like use open plaintext cookies, and doesn't have a full set of hooks for all occasions.
That said, these things are easy to fix with a PR that enables support for your use case.

# Quickstart

To install:
`go get github.com/kncept/fiber-oidc`

Example snippet:
```
	fiberOidc, err := fiberoidc.New(ctx, &fiberoidc.Config{
		Issuer:         "https://accounts.google.com",
		ClientId:       os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret:   os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectUri:    "http://localhost:3000/oauth2/callback",
		AuthCookieName: "bearer-auth",
	})
	if err != nil {
		return nil, err
	}

	app.Get(fiberOidc.CallbackPath(), fiberOidc.CallbackHandler())
	app.Get("/", fiberOidc.UnprotectedRoute(), func(c *fiber.Ctx) error {
		subject := "no auth present"
		idToken := fiberoidc.IdTokenFromContext(c)
		if idToken != nil {
			subject = idToken.Subject
		}
		return c.Render("index", subject)
	})
	app.Get("/me", fiberOidc.ProtectedRoute(), func(c *fiber.Ctx) error {
		idToken := fiberoidc.IdTokenFromContext(c)
		return c.Render("index", idToken.Subject)
	})
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
