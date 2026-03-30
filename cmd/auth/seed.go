// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package auth

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	larkauth "github.com/larksuite/cli/internal/auth"
	"github.com/larksuite/cli/internal/cmdutil"
	"github.com/larksuite/cli/internal/core"
	"github.com/larksuite/cli/internal/output"
)

// SeedOptions holds all inputs for auth seed.
type SeedOptions struct {
	Factory *cmdutil.Factory
	AppID   string
	AppSecret string
	Brand   string
	Token   string
	OpenID  string
	Name    string
}

// NewCmdAuthSeed creates the auth seed subcommand.
// This is an internal command used to securely inject a pre-authorized App/User context
// into the CLI's internal storage (e.g. from an AI Agent environment).
func NewCmdAuthSeed(f *cmdutil.Factory, runF func(*SeedOptions) error) *cobra.Command {
	opts := &SeedOptions{Factory: f}

	cmd := &cobra.Command{
		Use:    "seed",
		Short:  "Inject a pre-authorized context (Internal Use)",
		Hidden: true, // Hide from standard help output
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			return authSeedRun(opts)
		},
	}

	cmd.Flags().StringVar(&opts.AppID, "app-id", "", "App ID")
	cmd.Flags().StringVar(&opts.AppSecret, "app-secret", "", "App Secret")
	cmd.Flags().StringVar(&opts.Brand, "brand", "feishu", "Platform brand (feishu/lark)")
	cmd.Flags().StringVar(&opts.Token, "token", "", "User Access Token")
	cmd.Flags().StringVar(&opts.OpenID, "open-id", "", "User OpenID")
	cmd.Flags().StringVar(&opts.Name, "name", "AI User", "User Name")

	_ = cmd.MarkFlagRequired("app-id")
	_ = cmd.MarkFlagRequired("app-secret")
	_ = cmd.MarkFlagRequired("token")
	_ = cmd.MarkFlagRequired("open-id")

	return cmd
}

func authSeedRun(opts *SeedOptions) error {
	f := opts.Factory
	now := time.Now().UnixMilli()

	// 1. Save App Config
	// Create or load multi-config
	multi, _ := core.LoadMultiAppConfig()
	if multi == nil {
		multi = &core.MultiAppConfig{Apps: []core.AppConfig{}}
	}

	// Always override the first config slot for the seed injection 
	// (simplifies agent setup that assumes single-tenant environment)
	newApp := core.AppConfig{
		AppId:     opts.AppID,
		AppSecret: core.PlainSecret(opts.AppSecret),
		Brand:     core.LarkBrand(opts.Brand),
		DefaultAs: "user",
		Users: []core.AppUser{
			{UserOpenId: opts.OpenID, UserName: opts.Name},
		},
	}

	// Store AppSecret in keychain
	storableSecret, err := core.ForStorage(opts.AppID, newApp.AppSecret, f.Keychain)
	if err != nil {
		return output.Errorf(output.ExitInternal, "internal", "failed to store app secret: %v", err)
	}
	newApp.AppSecret = storableSecret

	if len(multi.Apps) > 0 {
		// Clean up old keychain tokens if app/user changes
		oldApp := multi.Apps[0]
		if oldApp.AppId != opts.AppID {
			core.RemoveSecretStore(oldApp.AppSecret, f.Keychain)
		}
		for _, u := range oldApp.Users {
			if oldApp.AppId != opts.AppID || u.UserOpenId != opts.OpenID {
				larkauth.RemoveStoredToken(oldApp.AppId, u.UserOpenId)
			}
		}
		multi.Apps[0] = newApp
	} else {
		multi.Apps = append(multi.Apps, newApp)
	}

	if err := core.SaveMultiAppConfig(multi); err != nil {
		return output.Errorf(output.ExitInternal, "internal", "failed to save config: %v", err)
	}

	// 2. Save UAT Token
	storedToken := &larkauth.StoredUAToken{
		UserOpenId:       opts.OpenID,
		AppId:            opts.AppID,
		AccessToken:      opts.Token,
		RefreshToken:     "", // Refreshes must be managed by the parent process
		ExpiresAt:        now + int64(7200)*1000, 
		RefreshExpiresAt: 0, 
		Scope:            "", // Assume all/provided by parent
		GrantedAt:        now,
	}

	if err := larkauth.SetStoredToken(storedToken); err != nil {
		return output.Errorf(output.ExitInternal, "internal", "failed to store user token: %v", err)
	}

	fmt.Fprintf(f.IOStreams.ErrOut, "Context seeded successfully for app %s, user %s\n", opts.AppID, opts.OpenID)
	return nil
}
