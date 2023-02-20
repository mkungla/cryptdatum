// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package bench

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/howijd/cryptdatum/devel/addons/cdtdevel/pkg/language"
	"github.com/mkungla/happy"
	"github.com/mkungla/happy/sdk/cli"
	"github.com/shopspring/decimal"
	"golang.org/x/exp/slog"
)

type PerfStat struct {
	outdir string
	cmds   map[string]PerfStatCommand
}
type PerfStatResult struct {
	CounterValue decimal.Decimal `json:"counter-value"`
	Unit         string          `json:"unit"`
	Event        string          `json:"event"`
	Variance     decimal.Decimal `json:"variance"`
	EventRuntime decimal.Decimal `json:"event-runtime"`
	PcntRunning  decimal.Decimal `json:"pcnt-running"`
	MetricValue  decimal.Decimal `json:"metric-value"`
	MetriUnit    string          `json:"metric-unit"`
}

type PerfStatCommand struct {
	Name        string
	Cmd         string
	Args        []string
	Results     map[string][]PerfStatResult
	Description string
}

func NewPerfStat(sess *happy.Session) *PerfStat {
	ps := &PerfStat{
		cmds: make(map[string]PerfStatCommand),
		outdir: filepath.Join(
			sess.Get("cryptdatum.build.dir").String(),
			"bench",
			"output",
		),
	}
	ps.cmds["file-info"] = PerfStatCommand{
		Cmd:         "file-info",
		Name:        "perf.stat.file-info",
		Description: "Print basic file info",
		Args:        []string{filepath.Join(sess.Get("cryptdatum.src.dir").String(), "spec/v1/testdata/valid-header-full-featured.cdt")},
		Results:     make(map[string][]PerfStatResult),
	}
	ps.cmds["file-has-header"] = PerfStatCommand{
		Cmd:         "file-has-header",
		Name:        "perf.stat.file-has-header",
		Description: "Performing minimal check to verify is external file has Cryptdatum header",
		Args:        []string{filepath.Join(sess.Get("cryptdatum.src.dir").String(), "spec/v1/testdata/valid-header-minimal.cdt")},
		Results:     make(map[string][]PerfStatResult),
	}
	ps.cmds["file-has-valid-header"] = PerfStatCommand{
		Cmd:         "file-has-valid-header",
		Name:        "perf.stat.file-has-valid-header",
		Description: "Performing full check to verify is external file containing valid Cryptdatum header",
		Args:        []string{filepath.Join(sess.Get("cryptdatum.src.dir").String(), "spec/v1/testdata/valid-header-full-featured.cdt")},
		Results:     make(map[string][]PerfStatResult),
	}
	ps.cmds["file-has-invalid-header"] = PerfStatCommand{
		Cmd:         "file-has-invalid-header",
		Name:        "perf.stat.file-has-invalid-header",
		Description: "Performing full check to verify is external file containing invalid Cryptdatum header",
		Args:        []string{filepath.Join(sess.Get("cryptdatum.src.dir").String(), "spec/v1/testdata/invalid-header-full-featured.cdt")},
		Results:     make(map[string][]PerfStatResult),
	}
	return ps
}

func (ps *PerfStat) Bench(sess *happy.Session, lang *language.Language, cmd string) error {
	command, ok := ps.cmds[cmd]
	if !ok {
		return fmt.Errorf("unknown perf stat command: %s lang: %s", cmd, lang.Lang)
	}

	resultfile := filepath.Join(
		ps.outdir,
		fmt.Sprintf("perf-stat-%s-%s-result.jsono", lang.Lang, cmd),
	)
	_ = os.MkdirAll(filepath.Dir(resultfile), 0700)

	args := []string{
		"stat",
		"--sync",
		"--repeat", "100",
		"--output", resultfile,
		"--json-output",
		"-e", "cpu-clock,task-clock,cache-misses,branch-misses,context-switches,cpu-cycles,instructions",
		lang.Config.Binary.Bin,
		cmd,
	}
	args = append(args, command.Args...)
	clicmd := exec.Command(
		"perf",
		args...,
	)
	res, err := cli.ExecCommand(sess, clicmd)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			fmt.Println(string(ee.Stderr))
		}
		fmt.Println(res)
		return err
	}

	// parse result
	result, err := os.ReadFile(resultfile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(result), "\n")
	var cmdPerfStatResults []PerfStatResult
	for _, line := range lines {
		// cline := strings.TrimSpace()
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var cmdPerfStatResult PerfStatResult
		if err := json.Unmarshal([]byte(line), &cmdPerfStatResult); err != nil {
			return err
		}

		cmdPerfStatResults = append(cmdPerfStatResults, cmdPerfStatResult)
	}
	command.Results[lang.Lang] = cmdPerfStatResults

	sess.Log().Ok("bench perf stats collected", slog.String("lang", lang.Lang), slog.String("cmd", cmd))

	return nil
}

func (ps *PerfStat) SupportsCmd(cmd string) bool {
	_, ok := ps.cmds[cmd]
	return ok
}

type langScore struct {
	Lang string
}

func (ps *PerfStat) CalculateScores(cmd PerfStatCommand) (map[string]decimal.Decimal, error) {
	scores := make(map[string]decimal.Decimal)

	var evhi = make(map[string]decimal.Decimal)
	var evlo = make(map[string]decimal.Decimal)

	for lang, res := range cmd.Results {

	}

	return scores, nil
}

func (b *Benchmarks) runPerfStat(sess *happy.Session) error {
	perttask := sess.Log().Task("bench with perf stat")

	perfstat := NewPerfStat(sess)

	for lang, bench := range b.Benchmarks {
		sess.Log().Info("bench perf stat", slog.String("lang", lang))

		for _, cmd := range bench.Lang.Config.Binary.Commands {
			if !perfstat.SupportsCmd(cmd) {
				continue
			}
			if err := perfstat.Bench(sess, bench.Lang, cmd); err != nil {
				return err
			}
		}
	}

	for _, cmd := range perfstat.cmds {
		br := BenchmarkResult{
			Name:        cmd.Name,
			Description: cmd.Description,
		}

		var err error
		br.Scores, err = perfstat.CalculateScores(cmd)
		if err != nil {
			return err
		}
		b.Results[cmd.Name] = br
	}
	sess.Log().Ok("perf stat done", perttask.LogAttr())
	return nil
}
