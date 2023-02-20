// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cdtdevel

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/howijd/cryptdatum/devel/addons/cdtdevel/pkg/language"
	"github.com/mkungla/happy"
)

func Addon() *happy.Addon {
	addon := happy.NewAddon(
		"cdtdevel",
		happy.Option("description", "Crypdatum source addon provides core development tools for Cryptdatum source and official libraries"),
	)

	api := &API{
		langs: make(map[string]*language.Language),
		cache: make(map[string]time.Time),
	}

	addon.OnRegister(func(sess *happy.Session, opts *happy.Options) (err error) {
		api.srcdir = sess.Get("cryptdatum.source.dir").String()
		if len(api.srcdir) == 0 {
			return errors.New("cryptdatum.source.dir is not set, check you settings")
		}
		lib := filepath.Join(api.srcdir, "lib")
		if err := sess.Set("cryptdatum.lib.dir", lib); err != nil {
			return err
		}
		if err := sess.Set("cryptdatum.build.dir", filepath.Join(api.srcdir, "build")); err != nil {
			return err
		}

		libdirLs, err := os.ReadDir(lib)
		if err != nil {
			return err
		}
		for _, lib := range libdirLs {
			if err := api.loadLanguageLibraries(sess, lib); err != nil {
				return err
			}
		}

		return nil
	})

	addon.ProvidesCommand(cmd(api))

	return addon
}

func cmd(api *API) *happy.Command {
	cmd := happy.NewCommand(
		"src",
		happy.Option("usage", "cardomizer source development tools: see cdt-devel src -h for more information."),
		happy.Option("category", "CARDOMIZER SOURCE"),
		happy.Option("description", `
	You only would need to use these tools when contributing Cryptdatum upstream.
	Before using these tools make sure you have read:
		- Contributing Guidelines	https://github.com/howijd/.github/blob/main/CONTRIBUTING.md
		- Contributor Covenant Code of Conduct https://github.com/howijd/.github/blob/main/CODE_OF_CONDUCT.md
		`),
	)

	cmd.AddSubCommand(buildCommand(api))
	cmd.AddSubCommand(testCommand(api))
	cmd.AddSubCommand(envCommand(api))
	cmd.AddSubCommand(benchCommand(api))
	return cmd
}
