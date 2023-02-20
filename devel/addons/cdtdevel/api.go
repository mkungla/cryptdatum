// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cdtdevel

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/howijd/cryptdatum/devel/addons/cdtdevel/pkg/language"
	"github.com/mkungla/happy"
	"github.com/mkungla/happy/pkg/vars"
	"golang.org/x/exp/slog"
)

type API struct {
	mu     sync.Mutex
	srcdir string
	langs  map[string]*language.Language

	cache map[string]time.Time
}

func (api *API) loadLanguageLibraries(sess *happy.Session, dir fs.DirEntry) error {
	lang := dir.Name()

	if !dir.IsDir() {
		return fmt.Errorf("not a direcory, unable to load language libraries %s", lang)
	}
	api.mu.Lock()
	defer api.mu.Unlock()

	if _, ok := api.langs[lang]; ok {
		return fmt.Errorf("language libraries already loaded")
	}
	src := filepath.Join(sess.Get("cryptdatum.lib.dir").String(), lang)
	sess.Log().Debug("loading libraries...", slog.String("language", dir.Name()), slog.String("src", src))

	conf, err := language.Load(sess, lang, src)
	if err != nil {
		return err
	}
	api.langs[lang] = conf
	return nil
}

// NewCryptdatumEnvMapper loads cryptdatum. keys from session and transforms these to
// Env mapper e.g. cryptdatum.source.dir becomes CRYPTDATUM_SRC_DIR
func (api *API) NewCryptdatumEnvMapper(sess *happy.Session) (*vars.Map, error) {
	api.mu.Lock()
	defer api.mu.Unlock()

	mapper, err := vars.ParseMapFromSlice(os.Environ())
	if err != nil {
		return nil, err
	}
	if err := mapper.Store(transformKey("cryptdatum.source.dir"), sess.Get("cryptdatum.source.dir")); err != nil {
		return nil, err
	}

	// load all cryptdatum. session variables
	copts, loaded := sess.RuntimeOpts().LoadWithPrefix("cryptdatum.")
	if !loaded {
		return mapper, nil
	}
	for _, opt := range copts.All() {
		if err := mapper.Store(transformKey(opt.Name()), opt.String()); err != nil {
			return nil, err
		}
	}
	return mapper, nil
}

func (api *API) EnvMapperForLanguage(sess *happy.Session, lang string) (*vars.Map, error) {
	mapper, err := api.NewCryptdatumEnvMapper(sess)
	if err != nil {
		return nil, err
	}

	api.mu.Lock()
	defer api.mu.Unlock()

	language, ok := api.langs[lang]
	if !ok {
		return nil, fmt.Errorf("language config not found for %s", lang)
	}
	// set defaults
	var envars = []struct {
		Key   string
		Value any
		RO    bool
	}{
		{"CDT_LANG", lang, true},
		{"CDT_SRC_DIR", language.Source, true},
		{"CDT_BUILD_DIR", filepath.Join(language.BuildDir), true},
	}

	for _, envar := range envars {
		if err := mapper.StoreReadOnly(envar.Key, envar.Value, envar.RO); err != nil {
			return nil, err
		}
	}

	// set language config global env if set
	for key, val := range language.Config.ENV {
		if err := mapper.StoreReadOnly(key, val, false); err != nil {
			return nil, err
		}
	}

	return mapper, nil
}

func transformKey(key string) string {
	return strings.ToUpper(strings.Replace(key, ".", "_", -1))
}
