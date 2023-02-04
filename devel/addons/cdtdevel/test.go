// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cdtdevel

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mkungla/happy"
	"github.com/mkungla/happy/sdk/cli"
	"github.com/sergi/go-diff/diffmatchpatch"
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

	if len(language.Config.Tests.Tasks) == 0 {
		slog.Warn("no tests", slog.String("lang", lang))
		return nil
	}

	for _, testTask := range language.Config.Tests.Tasks {
		if err := language.DoTask(sess, testTask, envmap); err != nil {
			return err
		}
	}

	api.mu.Unlock()

	if err := api.testCommandsExitCodes(sess, language); err != nil {
		return err
	}
	if err := api.testFileInfo(sess, language); err != nil {
		return err
	}

	sess.Log().Ok("done", buildTask.LogAttr())
	return nil
}

func (api *API) testFileInfo(sess *happy.Session, lang *Language) error {
	expected, err := os.ReadFile(filepath.Join(api.srcdir, "spec/v1/testdata/valid-header-full-featured-file-info.out"))
	if err != nil {
		return err
	}

	envmap, err := api.EnvMapperForLanguage(sess, lang.Lang)
	if err != nil {
		return err
	}

	testfile := filepath.Join(api.srcdir, "spec/v1/testdata/valid-header-full-featured.cdt")
	bin := os.Expand(lang.Config.Binary.Bin, envMapper(envmap))
	cmd := exec.Command(bin, []string{"file-info", testfile}...)

	out, err := cli.ExecCommandRaw(sess, cmd)
	if err != nil {
		return err
	}

	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(string(expected), string(out), false)

	if !bytes.Equal(out, expected) {
		fmt.Println(dmp.DiffPrettyText(diffs))
		return fmt.Errorf("file-info output mismatch lang: %s", lang.Lang)
	}
	sess.Log().Ok("file-info PASS", slog.String("lang", lang.Lang))
	return nil
}

func (api *API) testCommandsExitCodes(sess *happy.Session, lang *Language) error {
	testdatadir := filepath.Join(api.srcdir, "spec/v1/testdata")
	testdata, err := os.ReadDir(testdatadir)
	if err != nil {
		return err
	}

	var testfiles = make(map[string]string)
	for _, d := range testdata {
		if filepath.Ext(d.Name()) != ".cdt" || d.IsDir() {
			continue
		}
		testfiles[d.Name()] = filepath.Join(testdatadir, d.Name())
	}

	envmap, err := api.EnvMapperForLanguage(sess, lang.Lang)
	if err != nil {
		return err
	}
	bin := os.Expand(lang.Config.Binary.Bin, envMapper(envmap))

	// test file-has-header
	if lang.ProvidesCommand("file-has-header") {
		for tname, testfile := range testfiles {
			cmd := exec.CommandContext(sess, bin, []string{"file-has-header", testfile}...)
			_, err := cmd.CombinedOutput()
			if err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					fmt.Println(string(ee.Stderr))
				}
				return err
			}
			sess.Log().Ok(
				"file-has-header PASS",
				slog.String("lang", lang.Lang),
				slog.String("test", tname),
			)
		}
	} else {
		sess.Log().Warn("%s: does not support file-has-header")
	}

	// test file-has-valid-header
	if lang.ProvidesCommand("file-has-valid-header") {
		for tname, testfile := range testfiles {
			cmd := exec.CommandContext(sess, bin, []string{"file-has-valid-header", testfile}...)
			_, err := cmd.CombinedOutput()

			if strings.HasPrefix(tname, "valid-") {
				if err != nil {
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						fmt.Println(string(ee.Stderr))
					}
					return err
				}
				sess.Log().Ok(
					"file-has-valid-header PASS",
					slog.String("lang", lang.Lang),
					slog.String("test", tname),
				)
			} else if strings.HasPrefix(tname, "invalid-") {
				if err == nil {
					return fmt.Errorf("file-has-valid-header lang %s, expected non 0 exit code", lang.Lang)
				}
				var (
					ee       *exec.ExitError
					exitCode int
				)
				if errors.As(err, &ee) {
					exitCode = ee.ExitCode()
				}
				sess.Log().Ok(
					"file-has-valid-header PASS",
					slog.String("lang", lang.Lang),
					slog.String("test", tname),
					slog.Int("exitCode", exitCode),
				)
			} else {
				return fmt.Errorf("can not handle testdata file: %s", tname)
			}

		}
	} else {
		sess.Log().Warn("%s: does not support file-has-valid-header")
	}

	// test file-has-invalid-header
	if lang.ProvidesCommand("file-has-invalid-header") {
		for tname, testfile := range testfiles {
			cmd := exec.CommandContext(sess, bin, []string{"file-has-invalid-header", testfile}...)
			_, err := cmd.CombinedOutput()

			if strings.HasPrefix(tname, "invalid-") {
				if err != nil {
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						fmt.Println(string(ee.Stderr))
					}
					return err
				}
				sess.Log().Ok(
					"file-has-invalid-header PASS",
					slog.String("lang", lang.Lang),
					slog.String("test", tname),
				)
			} else if strings.HasPrefix(tname, "valid-") {
				if err == nil {
					return fmt.Errorf("file-has-invalid-header lang %s, expected non 0 exit code", lang.Lang)
				}
				var (
					ee       *exec.ExitError
					exitCode int
				)
				if errors.As(err, &ee) {
					exitCode = ee.ExitCode()
				}
				sess.Log().Ok(
					"file-has-invalid-header PASS",
					slog.String("lang", lang.Lang),
					slog.String("test", tname),
					slog.Int("exitCode", exitCode),
				)
			} else {
				return fmt.Errorf("can not handle testdata file: %s", tname)
			}

		}
	} else {
		sess.Log().Warn("%s: does not support file-has-invalid-header")
	}
	return nil
}
