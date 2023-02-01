#!/usr/bin/env python3
# Copyright 2022 The howijd.network Authors
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file.

from benchmark import *
from logging import INFO

bench = new_bench(INFO)

bench.add("Go", {
  "bin": "cryptdatum-go",
  "cmds": [
    "file-has-header",
    "file-has-valid-header",
    "file-has-invalid-header",
    "file-info",
  ]
})
bench.add("C", {
  "bin": "cryptdatum-c",
  "cmds": [
    "file-has-header",
    "file-has-valid-header",
    "file-has-invalid-header",
    "file-info",
  ]
})
bench.add("Rust", {
  "bin": "cryptdatum-rust",
  "cmds": [
    "file-has-header",
    "file-has-valid-header",
    "file-has-invalid-header",
    "file-info",
  ]
})
bench.add("ZIG", {
  "bin": "cryptdatum-zig",
  "cmds": [
    "file-has-header",
    "file-has-valid-header",
    "file-has-invalid-header",
    "file-info",
  ]
})

bench.run("File Is Crypdatum", ["file-has-header", bench.path("tests/spec/testdata/v1/valid-header-minimal.cdt")], "bench-file-has-header")
bench.run("File Has Valid Header", ["file-has-valid-header", bench.path("tests/spec/testdata/v1/valid-header-full-featured.cdt")], "bench-file-has-valid-header")
bench.run("File Has Invalid Header", ["file-has-invalid-header", bench.path("tests/spec/testdata/v1/invalid-header-full-featured.cdt")], "bench-file-has-invalid-header")
bench.run("File Info", ["file-info", bench.path("tests/spec/testdata/v1/valid-header-full-featured.cdt"), "1>/dev/null"], "bench-file-info")

bench.print()
