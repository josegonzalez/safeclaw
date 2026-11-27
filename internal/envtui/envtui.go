// Package envtui is the interactive menu for managing secrets.
package envtui

import (
	"errors"
	"fmt"
	"io"

	"charm.land/huh/v2"

	"github.com/josegonzalez/safeclaw/internal/secrets"
)

// Run shows the main menu until the user exits.
func Run(store secrets.Store, out io.Writer) error {
	for {
		var action string
		err := huh.NewSelect[string]().
			Title("What would you like to do?").
			Options(
				huh.NewOption("Manage keys", "manage"),
				huh.NewOption("Add key", "add"),
				huh.NewOption("Exit", "exit"),
			).
			Value(&action).
			Run()
		if errors.Is(err, huh.ErrUserAborted) {
			return nil
		}
		if err != nil {
			return err
		}
		switch action {
		case "manage":
			err = manageKeys(store, out)
		case "add":
			err = addKey(store, out)
		case "exit":
			return nil
		}
		if errors.Is(err, huh.ErrUserAborted) {
			continue
		}
		if err != nil {
			return err
		}
	}
}

func manageKeys(store secrets.Store, out io.Writer) error {
	keys, err := store.Keys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Fprint(out, "\nNo keys found.\n\n")
		return nil
	}

	opts := make([]huh.Option[string], 0, len(keys)+1)
	for _, k := range keys {
		opts = append(opts, huh.NewOption(k, k))
	}
	const back = "\x00back"
	opts = append(opts, huh.NewOption("← Back", back))

	fmt.Fprintf(out, "\nKeys from %s\n\n", store.Location())

	var key string
	if err := huh.NewSelect[string]().Title("Select key to delete:").Options(opts...).Value(&key).Run(); err != nil {
		return err
	}
	if key == back {
		return nil
	}

	confirmed := false
	if err := huh.NewConfirm().Title(fmt.Sprintf("Delete %s?", key)).Value(&confirmed).Run(); err != nil {
		return err
	}
	if !confirmed {
		fmt.Fprint(out, "\nCancelled.\n\n")
		return nil
	}
	if err := store.Delete(key); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nDeleted %s\n\n", key)
	return nil
}

func addKey(store secrets.Store, out io.Writer) error {
	fmt.Fprint(out, "\nExample: OPENAI_API_KEY\n\n")

	var name, value string
	err := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Name:").Value(&name).Validate(secrets.ValidateName),
		huh.NewInput().Title("Value:").EchoMode(huh.EchoModePassword).Value(&value).Validate(func(s string) error {
			if s == "" {
				return errors.New("value is required")
			}
			return nil
		}),
	)).Run()
	if err != nil {
		return err
	}

	if err := store.Set(name, value); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nSaved %s to %s\n", name, store.Location())
	fmt.Fprint(out, "Restart SafeClaw to use: safeclaw run\n\n")
	return nil
}
