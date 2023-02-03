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

func (api *API) buildAll(sess *happy.Session) error {
	task := sess.Log().Task("build all packages...")

	api.mu.Lock()
	langs := api.langs
	api.mu.Unlock()

	var errs error
	for lang := range langs {
		if err := api.buildLanguage(sess, lang); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	sess.Log().Ok("done", task.LogAttr())
	return errs
}

func (api *API) buildLanguage(sess *happy.Session, lang string) error {
	buildTask := sess.Log().Task("build language packages...", slog.String("language", lang))
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

	if len(language.Config.Build.Tasks) == 0 {
		slog.Warn("nothing to build", slog.String("lang", lang))
		return nil
	}
	for _, buildTask := range language.Config.Build.Tasks {
		if err := language.DoTask(sess, buildTask, envmap); err != nil {
			return err
		}
	}

	sess.Log().Ok("done", buildTask.LogAttr())
	return nil
}
