package auth_test

import (
	"testing"

	"github.com/go-modulus/auth"
	"github.com/go-modulus/auth/hash"
	"github.com/go-modulus/auth/repository"
	"github.com/go-modulus/auth/storage"
	"github.com/go-modulus/auth/storage/fixture"
	"github.com/go-modulus/modulus/module"
	"github.com/go-modulus/modulus/test"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"
)

var (
	passwordAuth       *auth.PasswordAuthenticator
	plainTokenAuth     *auth.PlainTokenAuthenticator
	fixtureFactory     *fixture.FixturesFactory
	hashStrategy       hash.TokenHashStrategy
	identityRepository repository.IdentityRepository
	accountRepository  repository.AccountRepository
)

func TestMain(m *testing.M) {
	test.LoadEnv(".")
	mod := auth.NewModule().
		AddProviders(
			func(db *pgxpool.Pool) storage.DBTX {
				return db
			},
			fixture.NewFixturesFactory,
		)

	test.TestMain(
		m,
		module.BuildFx(mod),
		fx.Populate(
			&passwordAuth,
			&plainTokenAuth,
			&fixtureFactory,
			&hashStrategy,
			&identityRepository,
			&accountRepository,
		),
	)
}
