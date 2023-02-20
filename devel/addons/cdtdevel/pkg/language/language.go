// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package language

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mkungla/happy"
	"github.com/mkungla/happy/pkg/vars"
	"github.com/mkungla/happy/sdk/cli"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"
	"gopkg.in/yaml.v3"
)

type Language struct {
	Lang     string         `json:"lang"`
	Source   string         `json:"-"`
	BuildDir string         `json:"-"`
	Config   LanguageConfig `json:"-"`
}

// Load loads specific language implementation of Cryptdatum
func Load(sess *happy.Session, lang, src string) (*Language, error) {
	c := &Language{
		Lang:   lang,
		Source: src,
	}
	c.BuildDir = filepath.Join(sess.Get("cryptdatum.source.dir").String(), "build/output", lang)
	if err := os.MkdirAll(c.BuildDir, 0700); err != nil {
		return nil, err
	}
	conffile, err := os.ReadFile(filepath.Join(c.Source, "cryptdatum.yml"))
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(conffile, &c.Config); err != nil {
		return nil, err
	}
	return c, nil
}

// LanguageConfig provides language specific configuration.
type LanguageConfig struct {
	ENV   map[string]string `yaml:"env"`
	Build struct {
		Tasks []Task `yaml:"tasks"`
	} `yaml:"build"`
	Tests struct {
		Tasks []Task `yaml:"tasks"`
	} `yaml:"tests"`
	Binary struct {
		Bin      string   `yaml:"bin"`
		Commands []string `yaml:"commands"`
	}
}

type Task struct {
	Name     string            `yaml:"name"`
	WD       string            `yaml:"wd"`
	Commands []string          `yaml:"commands"`
	Outputs  []string          `yaml:"outputs"`
	ENV      map[string]string `yaml:"env"`
}

func (l *Language) DoTask(sess *happy.Session, task Task, envmap *vars.Map) error {
	// set language config global env if set
	for key, val := range task.ENV {
		if err := envmap.Store(key, val); err != nil {
			return err
		}
		sess.Log().Debug("set env", slog.String("key", key), slog.String("value", val))
	}

	btask := sess.Log().Task(task.Name, slog.String("lang", l.Lang))

	wd := l.Source
	if task.WD != "" {
		wd = filepath.Join(wd, task.WD)
	}
	sess.Log().Debug("using working directory", slog.String("path", wd))

	sess.Log().Info("remove old output files", slog.String("task", task.Name))
	var outfiles []string
	for _, outfile := range task.Outputs {
		outfile = os.Expand(outfile, EnvMapper(envmap))
		if stat, err := os.Stat(outfile); err == nil && !stat.IsDir() {
			if err := os.Remove(outfile); err != nil {
				return err
			}
		}

		if err := os.MkdirAll(filepath.Dir(outfile), 0700); err != nil {
			return err
		}
		outfiles = append(outfiles, outfile)
	}

	sess.Log().Debug("execute task commands", slog.String("task", task.Name))
	for _, rawcmd := range task.Commands {
		cmd := prepareCommand(rawcmd, envmap)
		cmd.Dir = wd

		cmdtask := sess.Log().Task(
			fmt.Sprintf("%s: cmd", task.Name),
			slog.String("bin", cmd.Path),
			slog.Any("args", cmd.Args),
		)

		if err := cli.RunCommand(sess, cmd); err != nil {
			return err
		}

		sess.Log().Ok("command completed", cmdtask.LogAttr())
	}

	// check expected outputs
	sess.Log().Info("check for expected output files", slog.String("task", task.Name))
	for _, outfile := range outfiles {
		if _, err := os.Stat(outfile); err != nil {
			sess.Log().Warn("error checking expected output file", slog.String("file", outfile))
		} else {
			sess.Log().Ok("created", slog.String("file", outfile))
		}
	}

	sess.Log().Ok("task complete", btask.LogAttr())
	return nil
}

func (l *Language) ProvidesCommand(cmd string) bool {
	return slices.Contains(l.Config.Binary.Commands, cmd)
}

func EnvMapper(env *vars.Map) func(string) string {
	return func(key string) string {
		if env.Has(key) {
			return env.Get(key).String()
		}
		return ""
	}
}

func prepareCommand(rawcmd string, env *vars.Map) *exec.Cmd {
	expandedcmd := os.Expand(rawcmd, EnvMapper(env))
	rawcliargs := strings.Fields(expandedcmd)
	var (
		bin  string
		args []string
	)
	for _, arg := range rawcliargs {
		if arg == "\\" {
			continue
		}
		if bin == "" {
			bin = arg
		} else {
			args = append(args, arg)
		}
	}

	cmd := exec.Command(bin, args...)
	cmd.Env = env.ToKeyValSlice()

	return cmd
}
