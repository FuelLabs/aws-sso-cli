package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
 *
 * This program is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or with the authors permission any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"fmt"
	"os"
	"strings"
	// "github.com/davecgh/go-spew/spew"
)

const (
	ECS_PORT = 4144
)

type EcsCmd struct {
	Auth    EcsAuthCmd    `kong:"cmd,help='Manage the ECS Server/AWS Client authentication'"`
	SSL     EcsSSLCmd     `kong:"cmd,help='Manage the ECS Server SSL configuration'"`
	Server  EcsServerCmd  `kong:"cmd,help='Run the ECS Server locally'"`
	Docker  EcsDockerCmd  `kong:"cmd,help='Start the ECS Server in a Docker container'"`
	List    EcsListCmd    `kong:"cmd,help='List profiles loaded in the ECS Server'"`
	Load    EcsLoadCmd    `kong:"cmd,help='Load new IAM Role credentials into the ECS Server'"`
	Unload  EcsUnloadCmd  `kong:"cmd,help='Unload the current IAM Role credentials from the ECS Server'"`
	Profile EcsProfileCmd `kong:"cmd,help='Get the current role profile name in the default slot'"`
}

type EcsAuthCmd struct {
	BearerToken string `kong:"short=t,help='Bearer token value to use for ECS Server',xor='flag'"`
	Delete      bool   `kong:"short=d,help='Delete the current bearer token',xor='flag'"`
}

func (cc *EcsAuthCmd) Run(ctx *RunContext) error {
	// Delete the token
	if ctx.Cli.Ecs.Auth.Delete {
		return ctx.Store.DeleteEcsBearerToken()
	}

	// Or store the token in the SecureStore
	if ctx.Cli.Ecs.Auth.BearerToken == "" {
		return fmt.Errorf("no token provided")
	}
	if !strings.HasPrefix(ctx.Cli.Ecs.Auth.BearerToken, "Bearer ") {
		return fmt.Errorf("token should start with 'Bearer '")
	}
	return ctx.Store.SaveEcsBearerToken(ctx.Cli.Ecs.Auth.BearerToken)
}

type EcsSSLCmd struct {
	Save   EcsSSLSaveCmd   `kong:"cmd,help='Save a new SSL certificate/private key'"`
	Delete EcsSSLDeleteCmd `kong:"cmd,help='Delete the current SSL certificate/private key'"`
	Print  EcsSSLPrintCmd  `kong:"cmd,help='Print the current SSL certificate'"`
}

type EcsSSLSaveCmd struct {
	Certificate string `kong:"short=c,type='existingfile',help='Path to certificate chain PEM file',predictor='allFiles',required"`
	PrivateKey  string `kong:"short=p,type='existingfile',help='Path to private key file PEM file',predictor='allFiles'"`
	Force       bool   `kong:"hidden,help='Force loading the certificate'"`
}

type EcsSSLDeleteCmd struct{}

func (cc *EcsSSLDeleteCmd) Run(ctx *RunContext) error {
	return ctx.Store.DeleteEcsSslKeyPair()
}

type EcsSSLPrintCmd struct{}

func (cc *EcsSSLPrintCmd) Run(ctx *RunContext) error {
	cert, err := ctx.Store.GetEcsSslCert()
	if err != nil {
		return err
	}
	if cert == "" {
		return fmt.Errorf("no certificate found")
	}
	fmt.Println(cert)
	return nil
}

func (cc *EcsSSLSaveCmd) Run(ctx *RunContext) error {
	var privateKey, certChain []byte
	var err error

	if !ctx.Cli.Ecs.SSL.Save.Force {
		log.Warn("This feature is experimental and may not work as expected.")
		log.Warn("Please read https://github.com/synfinatic/aws-sso-cli/issues/936 before contiuing.")
		log.Fatal("Use `--force` to continue anyways.")
	}

	certChain, err = os.ReadFile(ctx.Cli.Ecs.SSL.Save.Certificate)
	if err != nil {
		return fmt.Errorf("failed to read certificate chain file: %w", err)
	}

	if ctx.Cli.Ecs.SSL.Save.PrivateKey != "" {
		privateKey, err = os.ReadFile(ctx.Cli.Ecs.SSL.Save.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
	}

	return ctx.Store.SaveEcsSslKeyPair(privateKey, certChain)
}
