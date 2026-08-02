package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/go-modulus/auth"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

type fakeAuthenticator struct {
	performer auth.Performer
	err       error
}

func (f *fakeAuthenticator) Authenticate(ctx context.Context, token string) (auth.Performer, error) {
	return f.performer, f.err
}

func TestGraphQLInitFuncFactory_InitFunc(t *testing.T) {
	t.Run(
		"passes the ctx and payload through unchanged when there is no Authorization", func(t *testing.T) {
			factory := auth.NewGraphQLInitFuncFactory(&fakeAuthenticator{})
			ctx := context.Background()
			payload := transport.InitPayload{}

			gotCtx, gotPayload, err := factory.InitFunc()(ctx, payload)

			require.NoError(t, err)
			require.Equal(t, ctx, gotCtx)
			require.Equal(t, auth.Performer{}, auth.GetPerformer(gotCtx))
			require.NotNil(t, gotPayload)
		},
	)

	t.Run(
		"authenticates the token from the connection_init payload and sets the performer", func(t *testing.T) {
			performerID := uuid.Must(uuid.NewV4())
			factory := auth.NewGraphQLInitFuncFactory(
				&fakeAuthenticator{performer: auth.Performer{ID: performerID}},
			)
			payload := transport.InitPayload{"Authorization": "Bearer abc123"}

			gotCtx, gotPayload, err := factory.InitFunc()(context.Background(), payload)

			require.NoError(t, err)
			require.NotNil(t, gotPayload)
			require.Equal(t, performerID, auth.GetPerformerID(gotCtx))
		},
	)

	t.Run(
		"also accepts a lowercase authorization key, same as InitPayload.Authorization", func(t *testing.T) {
			performerID := uuid.Must(uuid.NewV4())
			factory := auth.NewGraphQLInitFuncFactory(
				&fakeAuthenticator{performer: auth.Performer{ID: performerID}},
			)
			payload := transport.InitPayload{"authorization": "Bearer abc123"}

			gotCtx, _, err := factory.InitFunc()(context.Background(), payload)

			require.NoError(t, err)
			require.Equal(t, performerID, auth.GetPerformerID(gotCtx))
		},
	)

	t.Run(
		"rejects a malformed Authorization value with ErrInvalidToken", func(t *testing.T) {
			factory := auth.NewGraphQLInitFuncFactory(&fakeAuthenticator{})
			payload := transport.InitPayload{"Authorization": "not-a-bearer-token"}

			_, _, err := factory.InitFunc()(context.Background(), payload)

			require.ErrorIs(t, err, auth.ErrInvalidToken)
		},
	)

	t.Run(
		"maps a revoked token error to ErrUnauthenticated", func(t *testing.T) {
			factory := auth.NewGraphQLInitFuncFactory(&fakeAuthenticator{err: auth.ErrTokenIsRevoked})
			payload := transport.InitPayload{"Authorization": "Bearer abc123"}

			_, _, err := factory.InitFunc()(context.Background(), payload)

			require.ErrorIs(t, err, auth.ErrUnauthenticated)
		},
	)

	t.Run(
		"maps an expired token error to ErrUnauthenticated", func(t *testing.T) {
			factory := auth.NewGraphQLInitFuncFactory(&fakeAuthenticator{err: auth.ErrTokenIsExpired})
			payload := transport.InitPayload{"Authorization": "Bearer abc123"}

			_, _, err := factory.InitFunc()(context.Background(), payload)

			require.ErrorIs(t, err, auth.ErrUnauthenticated)
		},
	)

	t.Run(
		"propagates any other authenticator error instead of swallowing it", func(t *testing.T) {
			sentinel := errors.New("database is down")
			factory := auth.NewGraphQLInitFuncFactory(&fakeAuthenticator{err: sentinel})
			payload := transport.InitPayload{"Authorization": "Bearer abc123"}

			_, _, err := factory.InitFunc()(context.Background(), payload)

			require.ErrorIs(t, err, sentinel)
		},
	)

	t.Run(
		"rejects a nil-ID performer with ErrInvalidToken", func(t *testing.T) {
			factory := auth.NewGraphQLInitFuncFactory(&fakeAuthenticator{performer: auth.Performer{}})
			payload := transport.InitPayload{"Authorization": "Bearer abc123"}

			_, _, err := factory.InitFunc()(context.Background(), payload)

			require.ErrorIs(t, err, auth.ErrInvalidToken)
		},
	)
}
