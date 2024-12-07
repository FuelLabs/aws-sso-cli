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

	"github.com/synfinatic/aws-sso-cli/internal/awsconfig"
	"github.com/synfinatic/aws-sso-cli/internal/kubeconfig"
)

type SetupKubeCmd struct {
	Diff       bool   `kong:"help='Print a diff of changes to the config file instead of modifying it',xor='action'"`
	Force      bool   `kong:"help='Write a new config file without prompting'"`
	Print      bool   `kong:"help='Print profile entries instead of modifying config file',xor='action'"`
	AwsConfig  string `kong:"help='Path to AWS config file',env='AWS_CONFIG_FILE',default='~/.aws/config'"`
	KubeConfig string `kong:"help='Path to Kube config file',env='KUBE_CONFIG_FILE',default='~/.kube/config'"`
	RoleName   string `kong:"help='Role name to use for EKS info',default='EKS_DEV'"`
}

// AfterApply determines if SSO auth token is required
func (s SetupKubeCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_REQUIRED
	return nil
}

func (cc *SetupKubeCmd) Run(ctx *RunContext) error {
	var err error

	// always refresh our cache
	c := &CacheCmd{}
	if err = c.Run(ctx); err != nil {
		return err
	}

	fmt.Printf("Getting EKS cluster info with role %s...\n", cc.RoleName)
	eksClusters, err := kubeconfig.GetAllClusters(ctx.Settings, AwsSSO, cc.RoleName)
	if err != nil {
		return err
	}

	if ctx.Cli.Setup.Kube.Print {
		return kubeconfig.PrintKubeConfig(ctx.Settings, eksClusters, cc.RoleName)
	}

	err = awsconfig.UpdateAwsConfig(ctx.Settings, ctx.Cli.Setup.Kube.AwsConfig,
		ctx.Cli.Setup.Kube.Diff, ctx.Cli.Setup.Kube.Force)
	if err != nil {
		return err
	}

	return kubeconfig.UpdateKubeConfig(ctx.Settings, eksClusters, cc.RoleName, ctx.Cli.Setup.Kube.AwsConfig,
		ctx.Cli.Setup.Kube.Diff, ctx.Cli.Setup.Kube.Force)
}
