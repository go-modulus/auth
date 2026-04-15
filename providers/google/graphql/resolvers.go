package graphql

import (
	"context"

	"github.com/go-modulus/auth"
	"github.com/go-modulus/auth/graphql"
	"github.com/go-modulus/auth/providers/google/action"
	"github.com/go-modulus/modulus/errors/errtrace"
)

type Resolver struct {
	register *action.Register
}

func NewResolver(register *action.Register) *Resolver {
	return &Resolver{
		register: register,
	}
}

func (r *Resolver) RegisterViaGoogle(ctx context.Context, input RegisterViaGoogleInput) (graphql.TokenPair, error) {
	url := ""
	if input.RedirectURL != nil {
		url = *input.RedirectURL
	}

	tokens, err := r.register.Execute(
		ctx, action.RegisterInput{
			Code:        input.Code,
			Verifier:    input.Verifier,
			RedirectUrl: url,
			Roles:       input.Roles,
			UserInfo:    input.UserInfo,
		},
	)
	if err != nil {
		return graphql.TokenPair{}, errtrace.Wrap(err)
	}

	auth.SendRefreshToken(ctx, tokens.RefreshToken.Token.String)

	return graphql.TokenPair{
		AccessToken:  tokens.AccessToken.Token.String,
		RefreshToken: tokens.RefreshToken.Token.String,
	}, nil
}
