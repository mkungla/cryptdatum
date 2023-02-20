// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cdtdevel

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mkungla/happy"
)

func envCommand(api *API) *happy.Command {
	cmd := happy.NewCommand(
		"env",
		happy.Option("usage", "Print env for specific Cryptdatum language libraries"),
	)

	cmd.Do(func(sess *happy.Session, args happy.Args) error {
		if len(args.Args()) == 0 {
			return errors.New("missing argument 'all' or language to build")
		}
		lang := args.Arg(0).String()

		envmap, err := api.EnvMapperForLanguage(sess, lang)
		if err != nil {
			return err
		}
		elist := envmap.All()
		elistKeyLen := 0
		sort.Slice(elist, func(i, j int) bool {
			if l := len(elist[j].Name()); l > elistKeyLen {
				elistKeyLen = l
			}
			if l := len(elist[i].Name()); l > elistKeyLen {
				elistKeyLen = l
			}
			return elist[j].Name() > elist[i].Name()
		})

		envfmt := fmt.Sprintf("%%-%ds %%-10s %%s\n", elistKeyLen+1)
		for _, env := range elist {
			if !strings.HasPrefix(env.Name(), "CDT") && !strings.HasPrefix(env.Name(), "CRYPTDATUM") {
				continue
			}
			fmt.Printf(envfmt, env.Name(), env.Kind(), env.String())
		}
		return nil
	})
	return cmd
}
