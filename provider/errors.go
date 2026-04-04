package provider

import "errors"

var ErrNoAuth = errors.New("no auth supplied")
var ErrInitialization = errors.New("error in initialization")
var ErrNotAuthorized = errors.New("not authorized")
var ErrTokenExpired = errors.New("token is expired")

func errInitialization(err error) error {
	return ensure(err, ErrInitialization)
}

func ensure(err error, varErrType error) error {
	if errors.Is(err, varErrType) {
		return err
	}
	return errors.Join(err, varErrType)
}
