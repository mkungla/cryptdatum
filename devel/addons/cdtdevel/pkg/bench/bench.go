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

type Benchmarks struct {
	benchmarks map[string]*Benchmark
	results    *BenchmarkResults
}

func New() (*Benchmarks, error) {
	b := &Benchmarks{
		benchmarks: make(map[string]*Benchmark),
		results:    &BenchmarkResults{},
	}
	return b, nil
}

func (b *Benchmarks) Register(sess *happy.Session, lang *language.Language) error {

	if _, ok := b.benchmarks[lang.Lang]; ok {
		return fmt.Errorf("language already registered %s", lang.Lang)
	}
	b.benchmarks[lang.Lang] = &Benchmark{
		Lang:     lang,
		PerfStat: make(map[string][]PerfStatResult),
	}

	sess.Log().Ok(
		"add bench language",
		slog.String("lang", lang.Lang),
		slog.String("bin", lang.Config.Binary.Bin),
	)

	return nil
}

type Benchmark struct {
	Lang     *language.Language          `json:"language"`
	PerfStat map[string][]PerfStatResult `json:"perfStat"`
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

func (b *Benchmarks) Run(sess *happy.Session) error {

	_ = os.RemoveAll(filepath.Join(sess.Get("cryptdatum.build.dir").String(), "bench"))

	// perf stat
	if err := b.runPerfStat(sess); err != nil {
		return err
	}

	// save bench results
	for lang, bench := range b.benchmarks {
		resultfile := filepath.Join(
			sess.Get("cryptdatum.build.dir").String(),
			"bench",
			fmt.Sprintf("bench-%s-result.json", lang),
		)

		res, err := json.MarshalIndent(bench, "", "  ")
		if err != nil {
			return err
		}

		if err := os.WriteFile(resultfile, res, 0600); err != nil {
			return err
		}
	}

	return nil
}

func (b *Benchmarks) runPerfStat(sess *happy.Session) error {
	perttask := sess.Log().Task("bench with perf stat")

	for lang, bench := range b.benchmarks {
		sess.Log().Info("bench perf stat", slog.String("lang", lang))
		for _, cmd := range bench.Lang.Config.Binary.Commands {
			resultfile := filepath.Join(
				sess.Get("cryptdatum.build.dir").String(),
				"bench",
				"output",
				fmt.Sprintf("perf-stat-%s-%s-result.jsono", lang, cmd),
			)

			_ = os.MkdirAll(filepath.Dir(resultfile), 0700)

			args := []string{
				"stat",
				"--sync",
				"--repeat", "100",
				"--output", resultfile,
				"--json-output",
				"-e", "cpu-clock,task-clock,cache-misses,branch-misses,context-switches,cpu-cycles,instructions",
				bench.Lang.Config.Binary.Bin,
				cmd,
			}

			// exec perf
			switch cmd {
			case "file-info":
				args = append(args, filepath.Join(
					sess.Get("cryptdatum.src.dir").String(), "spec/v1/testdata/valid-header-full-featured.cdt"),
				)
				cmd := exec.Command(
					"perf",
					args...,
				)
				res, err := cli.ExecCommand(sess, cmd)
				if err != nil {
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						fmt.Println(string(ee.Stderr))
					}
					fmt.Println(res)
					return err
				}
			case "file-has-header":
				args = append(args, filepath.Join(
					sess.Get("cryptdatum.src.dir").String(), "spec/v1/testdata/valid-header-minimal.cdt"),
				)
				cmd := exec.Command(
					"perf",
					args...,
				)
				res, err := cli.ExecCommand(sess, cmd)
				if err != nil {
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						fmt.Println(string(ee.Stderr))
					}
					fmt.Println(res)
					return err
				}
			case "file-has-valid-header":
				args = append(args, filepath.Join(
					sess.Get("cryptdatum.src.dir").String(), "spec/v1/testdata/valid-header-full-featured.cdt"),
				)
				cmd := exec.Command(
					"perf",
					args...,
				)
				res, err := cli.ExecCommand(sess, cmd)
				if err != nil {
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						fmt.Println(string(ee.Stderr))
					}
					fmt.Println(res)
					return err
				}
			case "file-has-invalid-header":
				args = append(args, filepath.Join(
					sess.Get("cryptdatum.src.dir").String(), "spec/v1/testdata/invalid-header-full-featured.cdt"),
				)
				cmd := exec.Command(
					"perf",
					args...,
				)
				res, err := cli.ExecCommand(sess, cmd)
				if err != nil {
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						fmt.Println(string(ee.Stderr))
					}
					fmt.Println(res)
					return err
				}
			default:
				sess.Log().Warn("unsupported command for benchmark", slog.String("lang", lang), slog.String("cmd", cmd))
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

			bench.PerfStat[cmd] = cmdPerfStatResults
			sess.Log().Ok("bench perf stats collected", slog.String("lang", lang), slog.String("cmd", cmd))
		}
	}

	sess.Log().Ok("perf stat done", perttask.LogAttr())
	return nil
}

func (b *Benchmarks) Result(sess *happy.Session) error {

	result := make(BenchmarkResults)
	result["perf.stat.file-has-header"] = BenchmarkResult{
		Name:        "perf.stat.file-has-header",
		Description: "Performing minimal check to verify is external file has Cryptdatum header",
		Scores:      make(map[string]decimal.Decimal),
	}
	result["perf.stat.file-has-valid-header"] = BenchmarkResult{
		Name:        "perf.stat.file-has-valid-header",
		Description: "Performing full check to verify is external file containing valid Cryptdatum header",
		Scores:      make(map[string]decimal.Decimal),
	}
	result["perf.stat.file-has-invalid-header"] = BenchmarkResult{
		Name:        "perf.stat.file-has-invalid-header",
		Description: "Performing full check to verify is external file containing invalid Cryptdatum header",
		Scores:      make(map[string]decimal.Decimal),
	}
	result["perf.stat.file-info"] = BenchmarkResult{
		Name:        "perf.stat.file-info",
		Description: "Print basic file info",
		Scores:      make(map[string]decimal.Decimal),
	}

	// Get high scores which we can use for calculating the metric score deviation.
	for _, bench := range b.benchmarks {
		// perf stat high scores
		for cmd := range bench.PerfStat {
			key := fmt.Sprintf("perf.stat.%s", cmd)
			if _, ok := result[key]; !ok {
				return fmt.Errorf("unknown perf stats %s", key)
			}
			result[key].Scores[bench.Lang.Lang] = decimal.Zero.Copy()
		}
	}

	resultfile := filepath.Join(
		sess.Get("cryptdatum.build.dir").String(),
		"bench",
		"result-scores.json",
	)
	resb, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(resultfile, resb, 0600)
}

type BenchmarkResults map[string]BenchmarkResult

type BenchmarkResult struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	Scores      map[string]decimal.Decimal `json:"scores"` // lang => score
}
