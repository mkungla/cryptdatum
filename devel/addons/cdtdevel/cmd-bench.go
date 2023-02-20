// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cdtdevel

import (
	"os"

	"github.com/howijd/cryptdatum/devel/addons/cdtdevel/pkg/bench"
	"github.com/howijd/cryptdatum/devel/addons/cdtdevel/pkg/language"
	"github.com/mkungla/happy"
)

func benchCommand(api *API) *happy.Command {
	cmd := happy.NewCommand(
		"bench",
		happy.Option("usage", "benchmark Cryptdatum implementations"),
	)

	cmd.Do(func(sess *happy.Session, args happy.Args) error {
		b, err := bench.New()
		if err != nil {
			return err
		}

		// register language libraries for benchmarking
		for langName, lang := range api.langs {
			envmap, err := api.EnvMapperForLanguage(sess, langName)
			lang.Config.Binary.Bin = os.Expand(lang.Config.Binary.Bin, language.EnvMapper(envmap))

			if err != nil {
				return err
			}
			if err := b.Register(sess, lang); err != nil {
				return err
			}
		}

		// run benchmarks
		if err := b.Run(sess); err != nil {
			return err
		}

		return b.Result(sess)
	})
	return cmd
}
