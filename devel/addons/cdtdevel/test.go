// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cdtdevel

import (
	"errors"
	"fmt"

	"github.com/mkungla/happy"
	"golang.org/x/exp/slog"
)

func testCommand(api *API) *happy.Command {
	cmd := happy.NewCommand(
		"test",
		happy.Option("usage", "test Cryptdatum libraries and source code"),
	)

	cmd.Do(func(sess *happy.Session, args happy.Args) error {
		if len(args.Args()) == 0 {
			return errors.New("missing argument 'all' or language to build")
		}
		buildarg := args.Arg(0).String()
		if buildarg == "all" {
			return api.testAll(sess)
		}
		return api.testLanguage(sess, buildarg)
	})
	return cmd
}

func (api *API) testAll(sess *happy.Session) error {
	task := sess.Log().Task("test all packages...")
	api.mu.Lock()
	langs := api.langs
	api.mu.Unlock()

	var errs error
	for lang := range langs {
		if err := api.testLanguage(sess, lang); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	sess.Log().Ok("done", task.LogAttr())
	return errs
}

func (api *API) testLanguage(sess *happy.Session, lang string) error {
	buildTask := sess.Log().Task("test language source...", slog.String("language", lang))
	api.mu.Lock()

	language, loaded := api.langs[lang]
	if !loaded {
		api.mu.Unlock()
		return fmt.Errorf("no libraries loaded for language %s", lang)
	}

	api.mu.Unlock()
	envmap, err := api.EnvMapperForLanguage(sess, lang)
	if err != nil {
		return err
	}

	api.mu.Lock()
	defer api.mu.Unlock()

	if len(language.Config.Tests.Tasks) == 0 {
		slog.Warn("no tests", slog.String("lang", lang))
		return nil
	}
	for _, buildTask := range language.Config.Tests.Tasks {
		if err := language.DoTask(sess, buildTask, envmap); err != nil {
			return err
		}
	}

	sess.Log().Ok("done", buildTask.LogAttr())
	return nil
}
