// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

// Dynamic shell completion for the values the CLI can know: template names,
// credential IDs, and running wallet instances. Completions come from the
// active remote wallet when one is configured.

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/eudi-dev/eudi-dev/v2/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v2/internal/remote"
)

// completionClient uses a short timeout so remote completion stays responsive.
func completionClient() *remote.Client {
	url, err := activeRemoteURL()
	if err != nil || url == "" {
		return nil
	}
	c := remote.NewClient(url)
	c.HTTP.Timeout = 2 * time.Second
	return c
}

func completeTemplateNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var completions []string
	if c := completionClient(); c != nil {
		templates, err := c.Templates()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		for _, tpl := range templates {
			completions = append(completions, docString(tpl, "name")+"\t"+docString(tpl, "format"))
		}
		return completions, cobra.ShellCompDirectiveNoFileComp
	}

	loc, err := resolveTemplates()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	templates, err := credtemplate.List(loc)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	for _, tpl := range templates {
		completions = append(completions, tpl.Name+"\t"+tpl.Format)
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeCredentialIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var completions []string
	if c := completionClient(); c != nil {
		creds, err := c.Credentials()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		for _, cred := range creds {
			completions = append(completions, docString(cred, "id")+"\t"+docCredLabel(cred))
		}
		return completions, cobra.ShellCompDirectiveNoFileComp
	}

	// Loading a missing wallet creates it. Completion must not do that.
	store, err := openStore()
	if err != nil || !store.Exists() {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	w, err := store.LoadOrCreate()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	for _, cred := range w.GetCredentials() {
		completions = append(completions, cred.ID+"\t"+credLabel(cred))
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeDeferredIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	svc, err := managedWallet()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	pending, err := svc.DeferredIssuances()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var completions []string
	for _, entry := range pending {
		label := docCredLabel(entry)
		if label == "" {
			label = docString(entry, "credential_configuration_id")
		}
		completions = append(completions, docString(entry, "id")+"\t"+label)
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeInstanceTargets(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var completions []string
	for _, inst := range remote.Discover(500 * time.Millisecond) {
		desc := fmt.Sprintf("pid %d", inst.PID)
		if inst.WalletDir != "" {
			desc += " " + inst.WalletDir
		}
		completions = append(completions, inst.URL+"\t"+desc)
		completions = append(completions, strconv.Itoa(inst.Port)+"\t"+inst.URL)
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeUseTargets(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	completions := []string{"local\tmanage the local wallet store"}
	for _, inst := range remote.Discover(500 * time.Millisecond) {
		desc := fmt.Sprintf("pid %d", inst.PID)
		if inst.WalletDir != "" {
			desc += " " + inst.WalletDir
		}
		completions = append(completions, inst.URL+"\t"+desc)
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func completeRemoteFlag(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return completeUseTargets(cmd, nil, toComplete)
}

func staticCompletion(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}
