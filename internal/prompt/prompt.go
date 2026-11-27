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
	// Login signs in and returns a new Claude Code token. When set, the
	// Claude token prompt offers it alongside pasting a token.
	Login func() (string, error)
}

// ClaudeToken implements session.Prompter.
func (t Terminal) ClaudeToken() (string, error) {
	fmt.Fprint(t.Out, `
=== Claude Code setup ===

No Claude Code token found. Let's set one up.
`)
	if t.Login != nil {
		choice := "login"
		err := huh.NewSelect[string]().
			Title("How do you want to set it up?").
			Options(
				huh.NewOption("Sign in now (runs `claude setup-token` in a container)", "login"),
				huh.NewOption("Paste an existing token", "paste"),
			).
			Value(&choice).
			Run()
		if err != nil {
			return "", err
		}
		if choice == "login" {
			tok, err := t.Login()
			if err != nil {
				return "", err
			}
			fmt.Fprintln(t.Out, "Saved.")
			return tok, nil
		}
	}
	fmt.Fprint(t.Out, `
Run one of these in another terminal:

  safeclaw auth login
  claude setup-token

Either generates a long-lived OAuth token (valid for 1 year).
Paste the token below.

`)
	tok, err := Secret("Token:", true)
	if err != nil {
		return "", err
	}
	fmt.Fprintln(t.Out, "Saved.")
	return tok, nil
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
	tok, err := Secret("Token:", false)
	if err != nil {
		return "", err
	}
	if tok == "" {
		fmt.Fprintln(t.Out, "No token provided, skipping. You can set it up later with `safeclaw env set GH_TOKEN`.")
		return "", nil
	}
	fmt.Fprintln(t.Out, "Saved.")
	return tok, nil
}

// Secret asks for a value with hidden input and returns it with surrounding
// whitespace removed. A required value can't be left empty.
func Secret(title string, required bool) (string, error) {
	var v string
	in := huh.NewInput().Title(title).EchoMode(huh.EchoModePassword).Value(&v)
	if required {
		in = in.Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return errors.New("a value is required")
			}
			return nil
		})
	}
	if err := in.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(v), nil
}
