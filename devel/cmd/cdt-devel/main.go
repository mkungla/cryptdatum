// Copyright 2023 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/howijd/cryptdatum/devel/addons/cdtdevel"
	"github.com/mkungla/happy"
	"github.com/mkungla/happy/pkg/vars"
	"github.com/mkungla/happy/sdk/cli"
	"github.com/mkungla/happy/sdk/commands"
)

func main() {
	app := happy.New(
		happy.Option("app.name", "Cryptdatum Devel"),
		happy.Option("app.slug", "cryptdatum-devel"),
		happy.Option("app.description", "Cryptdatum development tool chain"),
		happy.Option("app.copyright.by", "The howijd.network Authors"),
		happy.Option("app.copyright.since", 2023),
		happy.Option("app.license", "Apache License, Version 2.0"),
		happy.Option("app.throttle.ticks", time.Minute/6),
		happy.Option("app.cron.on.service.start", false),
		happy.Option("app.fs.enabled", true),
		happy.Option("log.level", happy.LogLevelTask),
		happy.Option("log.stdlog", true),
		happy.Option("log.source", false),
		happy.Option("log.colors", true),
	)

	app.Setting("cryptdatum.source.dir", "", "", func(key string, val vars.Value) error {
		if _, err := os.Stat(val.String()); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("cryptdatum source directory does not exist")
			} else {
				return err
			}
		}
		// use spec as validation point of Cryptdatum source
		specpath := filepath.Join(val.String(), "spec", "v1", "specification.md")
		if _, err := os.Stat(specpath); err != nil {
			return fmt.Errorf("unable to locate spec file at %s, make sure that cryptdatum.source.dir points to Cryptdatum source directory", specpath)
		}
		return nil
	})

	app.AddCommand(commands.Info())
	app.AddCommand(commands.Reset())

	app.WithAddons(
		cdtdevel.Addon(),
	)

	app.OnInstall(func(sess *happy.Session) error {
		srcdir := cli.AskForInput("enter path to cryptsdatum source code")
		if err := sess.Set("cryptdatum.source.dir", srcdir); err != nil {
			return err
		}
		return nil
	})

	app.Main()
}
