package email

import (
	"github.com/go-modulus/auth"
	"github.com/go-modulus/auth/providers/email/action"
	"github.com/go-modulus/auth/providers/email/graphql"
	"github.com/go-modulus/modulus/captcha"
	"github.com/go-modulus/modulus/module"
)

func NewModule(options ...module.Option) *module.Module {
	return module.NewModule("modulus/auth/email").
		// Add all dependencies of a module here
		AddDependencies(
			auth.NewModule(),
			captcha.NewModule(),
		).
		// Add all your services here. DO NOT DELETE AddProviders call. It is used for code generation
		AddProviders(
			action.NewLogin,
			action.NewRegister,
			action.NewResetPassword,
			action.NewChangePassword,
			graphql.NewResolver,
		).
		SetOverriddenProvider("auth.email.UserCreator", action.NewDefaultUserCreator).
		SetOverriddenProvider("auth.email.VerifiedEmailChecker", action.NewDefaultVerifiedEmailChecker).
		SetOverriddenProvider("auth.email.MailSender", action.NewDefaultMailSender).
		// Add all your CLI commands here
		AddCliCommands().
		// Add all your configs here
		InitConfig(action.ResetPasswordConfig{}).
		WithOptions(options...)
}

func NewManifesto() module.Manifesto {
	emailModule := module.NewManifesto(
		NewModule(),
		"github.com/go-modulus/auth/providers/email",
		"A provider for auth module to organize authentication via the email/password pair.",
		"1.0.0",
	)
	emailModule.Install.AppendFiles(
		module.InstalledFile{
			SourceUrl: "https://raw.githubusercontent.com/go-modulus/auth/refs/heads/main/providers/email/graphql/auth.graphql",
			DestFile:  "internal/auth/providers/email/graphql/auth.graphql",
		},
	)
	emailModule.LocalPath = "internal/auth/providers/email"
	return emailModule
}

func OverrideUserCreator[T action.UserCreator](authModule *module.Module) *module.Module {
	return authModule.SetOverriddenProvider("auth.email.UserCreator", func(impl T) action.UserCreator { return impl })
}

func OverrideVerifiedEmailChecker[T action.VerifiedEmailChecker](authModule *module.Module) *module.Module {
	return authModule.SetOverriddenProvider(
		"auth.email.VerifiedEmailChecker",
		func(impl T) action.VerifiedEmailChecker { return impl },
	)
}

func OverrideMailSender[T action.MailSender](authModule *module.Module) *module.Module {
	return authModule.SetOverriddenProvider("auth.email.MailSender", func(impl T) action.MailSender { return impl })
}
