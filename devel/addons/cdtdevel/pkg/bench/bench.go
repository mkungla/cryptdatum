// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/howijd/cryptdatum/devel/addons/cdtdevel/pkg/language"
	"github.com/mkungla/happy"
	"github.com/shopspring/decimal"
	"golang.org/x/exp/slog"
)

type Benchmarks struct {
	Benchmarks map[string]*Benchmark `json:"benchmarks"`
	Results    BenchmarkResults      `json:"results"`
}

func New() (*Benchmarks, error) {
	b := &Benchmarks{
		Benchmarks: make(map[string]*Benchmark),
		Results:    make(BenchmarkResults),
	}
	return b, nil
}

func (b *Benchmarks) Register(sess *happy.Session, lang *language.Language) error {

	if _, ok := b.Benchmarks[lang.Lang]; ok {
		return fmt.Errorf("language already registered %s", lang.Lang)
	}
	b.Benchmarks[lang.Lang] = &Benchmark{
		Lang: lang,
	}

	sess.Log().Ok(
		"add bench language",
		slog.String("lang", lang.Lang),
		slog.String("bin", lang.Config.Binary.Bin),
	)

	return nil
}

type Benchmark struct {
	Lang *language.Language `json:"language"`
}

func (b *Benchmarks) Run(sess *happy.Session) error {

	_ = os.RemoveAll(filepath.Join(sess.Get("cryptdatum.build.dir").String(), "bench"))

	// perf stat
	if err := b.runPerfStat(sess); err != nil {
		return err
	}
	return nil
}

func (b *Benchmarks) Result(sess *happy.Session) error {
	// Get high scores which we can use for calculating the metric score deviation.
	resultfile := filepath.Join(
		sess.Get("cryptdatum.build.dir").String(),
		"bench",
		"result-scores.json",
	)
	resb, err := json.MarshalIndent(b.Results, "", "  ")
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
