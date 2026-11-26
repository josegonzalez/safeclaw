// Package prompt asks for missing tokens on first run.
package prompt

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"charm.land/huh/v2"
)

// Terminal prompts on the terminal with huh.
type Terminal struct {
	Out io.Writer
}

// ClaudeToken implements session.Prompter.
func (t Terminal) ClaudeToken() (string, error) {
	fmt.Fprint(t.Out, `
=== Claude Code setup ===

No Claude Code token found. Let's set one up.

Run this command in another terminal:

  claude setup-token

It will generate a long-lived OAuth token (valid for 1 year).
Paste the token below.

`)
	var tok string
	err := huh.NewInput().
		Title("Token:").
		EchoMode(huh.EchoModePassword).
		Value(&tok).
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return errors.New("token is required, run 'claude setup-token' and paste the result")
			}
			return nil
		}).
		Run()
	if err != nil {
		return "", err
	}
	fmt.Fprintln(t.Out, "Saved.")
	return strings.TrimSpace(tok), nil
}

// GitHubToken implements session.Prompter.
func (t Terminal) GitHubToken() (string, error) {
	fmt.Fprint(t.Out, `
=== GitHub CLI setup ===

No GitHub token found. Let's set one up.

We recommend creating a separate GitHub account for SafeClaw
so you can scope its permissions independently.

Once logged in, run this in another terminal:

  gh auth token

Or create a Personal Access Token at:
  https://github.com/settings/tokens

Paste the token below, or leave it empty to skip.

`)
	var tok string
	if err := huh.NewInput().Title("Token:").EchoMode(huh.EchoModePassword).Value(&tok).Run(); err != nil {
		return "", err
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		fmt.Fprintln(t.Out, "No token provided, skipping. You can set it up later by re-running this command.")
		return "", nil
	}
	fmt.Fprintln(t.Out, "Saved.")
	return tok, nil
}
