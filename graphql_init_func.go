package auth

import (
	"context"
	"errors"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/go-modulus/modulus/errors/errtrace"
	"github.com/go-modulus/modulus/logger"
	"github.com/gofrs/uuid"
)

// GraphQLInitFuncFactory authenticates GraphQL WebSocket subscription
// connections the same way Middleware authenticates regular HTTP requests,
// putting the resulting Performer into the context for the resolvers.
//
// The one difference is where the access token comes from: browsers can't
// set custom headers on a WebSocket handshake, so graphql-ws/graphql-transport-ws
// clients send it in the connection_init payload instead of an Authorization
// header. See transport.InitPayload.Authorization, which looks for an
// "Authorization"/"authorization" key in that payload.
//
// Register it with a graphql module via:
//
//	graphql.AddInitFuncFactory[*auth.GraphQLInitFuncFactory](rank)
type GraphQLInitFuncFactory struct {
	authenticator Authenticator
}

func NewGraphQLInitFuncFactory(authenticator Authenticator) *GraphQLInitFuncFactory {
	return &GraphQLInitFuncFactory{authenticator: authenticator}
}

func (f *GraphQLInitFuncFactory) InitFunc() transport.WebsocketInitFunc {
	return func(
		ctx context.Context, initPayload transport.InitPayload,
	) (context.Context, *transport.InitPayload, error) {
		authorization := initPayload.Authorization()
		if authorization == "" {
			return ctx, &initPayload, nil
		}

		token, err := parseAccessToken(authorization)
		if err != nil {
			return ctx, nil, err
		}

		performer, err := f.authenticator.Authenticate(ctx, token)
		if err != nil {
			if errors.Is(err, ErrTokenIsRevoked) || errors.Is(err, ErrTokenIsExpired) {
				return ctx, nil, ErrUnauthenticated
			}
			return ctx, nil, errtrace.Wrap(err)
		}
		if performer.ID == uuid.Nil {
			return ctx, nil, ErrInvalidToken
		}

		ctx = WithPerformer(ctx, performer)
		ctx = logger.AddTags(ctx, "performerId", performer.ID.String())

		return ctx, &initPayload, nil
	}
}
