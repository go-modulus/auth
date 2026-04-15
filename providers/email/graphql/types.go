package graphql

import (
	captchaAction "github.com/go-modulus/modulus/captcha/action"
	"github.com/gofrs/uuid"
)

type EmailSignUpInput struct {
	Email    string                      `json:"email"`
	Password string                      `json:"password"`
	Captcha  *captchaAction.CaptchaToken `json:"captcha"`
	// The unique identifier of the user.
	// It will be used as the ID in the account table.
	// If empty, it will be generated automatically.
	ID uuid.UUID `json:"-"`
	// Additional user fields that may be stored in the account table.
	// It has to be set in the wrapper resolver instead of the GraphQL query if needed.
	UserInfo map[string]interface{} `json:"-"`
	// A set of roles that will be assigned to the user during registration.
	// It has to be set in the wrapper resolver instead of the GraphQL query if needed.
	// By default, the user will be assigned the role "user".
	Roles []string `json:"-"`
}

type EmailSignInInput struct {
	Email    string                      `json:"email"`
	Password string                      `json:"password"`
	Captcha  *captchaAction.CaptchaToken `json:"captcha"`
}
