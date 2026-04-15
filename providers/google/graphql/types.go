package graphql

type RegisterViaGoogleInput struct {
	Code        string  `json:"code"`
	Verifier    string  `json:"verifier"`
	RedirectURL *string `json:"redirectUrl"`
	// Additional user fields that may be stored in the account table.
	// It has to be set in the wrapper resolver instead of the GraphQL query if needed.
	UserInfo map[string]interface{} `json:"-"`
	// A set of roles that will be assigned to the user during registration.
	// It has to be set in the wrapper resolver instead of the GraphQL query if needed.
	// By default, the user will be assigned the role "user".
	Roles []string `json:"-"`
}
