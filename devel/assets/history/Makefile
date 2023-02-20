# That's our default target when none is given on the command line

CDT_BUILD_OUTPUT = ./build

# Get Version information
CDT_VERSION_FULL 								:= $(shell git describe --match "v*" --always --tags)
cdt_version_full_parts 					:= $(subst -, ,$(CDT_VERSION_FULL))
CDT_VERSION_TAG        					:= $(word 1,$(cdt_version_full_parts))
CDT_VERSION_COMMITS_SINCE_TAG  	:= $(word 2,$(cdt_version_full_parts))
CDT_VERSION_COMMIT_SHORT  			:= $(word 3,$(cdt_version_full_parts))
CDT_VERSION_COMMIT_LONG 	 			:= $(shell git rev-parse HEAD)
CDT_VERSION            					:= $(subst v,,$(CDT_VERSION_TAG))
cdt_version_parts      					:= $(subst ., ,$(CDT_VERSION))
CDT_VERSION_MAJOR              	:= $(word 1,$(cdt_version_parts))
CDT_VERSION_MINOR              	:= $(word 2,$(cdt_version_parts))
CDT_VERSION_PATCH              	:= $(word 3,$(cdt_version_parts))

# If CDT_BUILD_VERBOSE equals 0 then the above command will be hidden.
# If CDT_BUILD_VERBOSE equals 1 then the above command is displayed.
# If CDT_BUILD_VERBOSE equals 2 then give the reason why each target is rebuilt.
CDT_BUILD_VERBOSE = 2

ifeq ($(filter undefine,$(.FEATURES)),)
$(error GNU Make >= 3.82 is required. Your Make version is $(MAKE_VERSION))
endif

# That's our default target when none is given on the command line
PHONY := help
help:
	@echo  'CRYPTDATUM MAKEFILE'
	@echo  ''
	@echo  'BINARIES:'
	@echo  '  bin 			- build all binaries'
	@echo  '  bin-c	  		- build C cli tool'
	@echo  '  bin-go	  	- build Go cli tool'
	@echo  '  bin-rust	  	- build Rust cli tool'
	@echo  '  bin-zig 	  	- build ZIG cli tool'
	@echo  ''
	@echo  'LIBRARIES:'
	@echo  '  lib-rust	  	- build rust library'
	@echo  ''
	@echo  'TESTS:'
	@echo  '  test		  	- run all tests'
	@echo  '  test-c		- test C source'
	@echo  '  test-cpp		- test C++ source'
	@echo  '  test-go		- test Go source'
	@echo  '  test-rust		- test Rust source'
	@echo  '  test-zig		- test ZIG source'
	@echo  ''
	@echo  'BENCHMARKS:'
	@echo  '  bench		  	- run all benchmarks'
	@echo  ''
	@echo  'SPECS:'
	@echo  '  spec-v1-gen-testdata	- generate tastdata for specification v1'
	@echo  ''
	@echo  'GENERAL:'
	@echo  '  clean		  	- remove most generated files but keep the config and'
	@echo  '            	       	  enough build support to build external modules'
	@echo  '  env	  		- print make config'
	@echo  '  version	  	- print verision info which would be used by build'
	@echo  ''

# Avoid interference with shell env settings
unexport GREP_OPTIONS

# If the user is running make -s (silent mode), suppress echoing of
# commands
# make-4.0 (and later) keep single letter options in the 1st word of MAKEFLAGS.
silence:=$(findstring s,$(filter-out --%,$(MAKEFLAGS)))

ifeq ($(silence),s)
CDT_BUILD_VERBOSE = 0
endif

export CDT_BUILD_VERBOSE

ifneq ($(CDT_BUILD_OUTPUT),)
this-makefile := $(lastword $(MAKEFILE_LIST))

# Make's built-in functions such as $(abspath ...), $(realpath ...) cannot
# expand a shell special character '~'. We use a somewhat tedious way here.
CDT_BUILD_DIR := $(shell mkdir -p $(CDT_BUILD_OUTPUT)/{bin,lib,tests} && cd $(CDT_BUILD_OUTPUT) && pwd)
$(if $(CDT_BUILD_DIR),, \
     $(error failed to create output directory "$(CDT_BUILD_OUTPUT)"))
# $(realpath ...) resolves symlinks
CDT_BUILD_DIR := $(realpath $(CDT_BUILD_DIR))
else
CDT_BUILD_DIR := $(CURDIR)
endif # ifneq ($(CDTBUILD_OUTPUT),)

CDT_BUILD_BIN_DIR = $(CDT_BUILD_DIR)/bin
CDT_BUILD_TEST_DIR = $(CDT_BUILD_DIR)/tests
CDT_BUILD_LIB_DIR = $(CDT_BUILD_DIR)/lib
CDT_BENCH_DIR = $(CDT_SRC_DIR)/tests/bench
CDT_SRC_DIR := $(realpath $(dir $(this-makefile)))
CDT_CMD_DIR := $(CDT_SRC_DIR)/cmd
CDT_TESTDATA_DIR = ${CDT_SRC_DIR}/tests/spec/testdata

# C
CDT_C_BIN = $(CDT_BUILD_BIN_DIR)/cryptdatum-c
# GO
CDT_GO_BIN = $(CDT_BUILD_BIN_DIR)/cryptdatum-go
# RUST
CDT_RUST_LIB = $(CDT_BUILD_LIB_DIR)/libcryptdatum.rlib
CDT_RUST_BIN = $(CDT_BUILD_BIN_DIR)/cryptdatum-rust
# ZIG
CDT_ZIG_BIN = $(CDT_BUILD_BIN_DIR)/cryptdatum-zig

ifneq ($(words $(subst :, ,$(CDT_SRC_DIR))), 1)
$(error source directory cannot contain spaces or colons)
endif

# Do not print "Entering directory ...",
# but we want to display it when entering to the output directory
# so that IDEs/editors are able to understand relative filenames.
MAKEFLAGS += --no-print-directory

define test_bin_cmd_exit_code
	@$(1) $(2) $(3); \
	LAST_EXIT_CODE=$$?; \
	cmd_bin_name=$(notdir $1); \
	testdata_file_name=$(notdir $3); \
	if [ $$LAST_EXIT_CODE -eq $(4) ]; \
	then \
		echo "test(PASSED) $$cmd_bin_name $(2) $$testdata_file_name"; \
	else \
		echo "test(FAILED): Unexpected exit code '$$LAST_EXIT_CODE' want '$(4)' $(1) $(2) $(3)"; \
		exit 1; \
	fi
endef

####################
# BINARIES
####################
# build all binaries and deps
PHONY += bin
bin: bin-c bin-rust bin-go

PHONY += bin-c
bin-c:
	@gcc -o $(CDT_BUILD_BIN_DIR)/cryptdatum-c \
		$(CDT_CMD_DIR)/cryptdatum.c \
		cryptdatum.c

PHONY += bin-go
bin-go:
	@go build -o $(CDT_GO_BIN) $(CDT_CMD_DIR)/cryptdatum.go

PHONY += bin-rust
bin-rust: lib-rust
	@rustc $(CDT_CMD_DIR)/cryptdatum.rs \
		--extern cryptdatum=$(CDT_RUST_LIB) \
		--edition 2021 \
		--crate-type bin \
		-C debuginfo=0 \
		-C opt-level=3 \
		-o $(CDT_BUILD_BIN_DIR)/cryptdatum-rust

PHONY += bin-zig
bin-zig:
	zig build-exe \
		-femit-bin=$(CDT_ZIG_BIN) \
		$(CDT_SRC_DIR)/zig/cryptdatum.zig

####################
# LIBRARIES
####################
PHONY += lib-rust
lib-rust:
	@rustc $(CDT_SRC_DIR)/cryptdatum.rs \
		--crate-type=lib \
		-C debuginfo=0 \
		-C opt-level=3 \
		-o $(CDT_RUST_LIB)

####################
# TESTS
####################
PHONY += test
test: test-c test-go test-rust

PHONY += test-c
test-c: bin-c
	@echo 'TEST C RUNNING'
	@gcc -o $(CDT_BUILD_TEST_DIR)/cryptdatum-c-test \
		cryptdatum_test.c \
		cryptdatum.c \
		&& $(CDT_BUILD_TEST_DIR)/cryptdatum-c-test
	$(call test_bin_cmd_exit_code, $(CDT_C_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_C_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.ct,1)
	$(call test_bin_cmd_exit_code, $(CDT_C_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/valid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_C_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/valid-header-minimal.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_C_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.cdt,1)
	$(call test_bin_cmd_exit_code, $(CDT_C_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/valid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_C_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/valid-header-minimal.cdt,0)
	@echo 'TEST C DONE'

PHONY += test-go
test-go: bin-go
	@echo 'TEST GO RUNNING'
	@go test -cover .
	$(call test_bin_cmd_exit_code, $(CDT_GO_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_GO_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.ct,1)
	$(call test_bin_cmd_exit_code, $(CDT_GO_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/valid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_GO_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/valid-header-minimal.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_GO_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.cdt,1)
	$(call test_bin_cmd_exit_code, $(CDT_GO_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/valid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_GO_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/valid-header-minimal.cdt,0)
	@echo 'TEST GO DONE'

PHONY += test-rust
test-rust: bin-rust
	@echo 'TEST RUST RUNNING'
	@cargo test
	$(call test_bin_cmd_exit_code, $(CDT_RUST_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_RUST_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.ct,1)
	$(call test_bin_cmd_exit_code, $(CDT_RUST_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/valid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_RUST_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/valid-header-minimal.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_RUST_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.cdt,1)
	$(call test_bin_cmd_exit_code, $(CDT_RUST_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/valid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_RUST_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/valid-header-minimal.cdt,0)
	@echo 'TEST RUST DONE'

PHONY += test-zig
test-zig: bin-zig
	@echo 'TEST ZIG RUNNING'
	zig test $(CDT_SRC_DIR)/zig/cryptdatum/cryptdatum.zig
	zig test $(CDT_SRC_DIR)/zig/cryptdatum.zig
	$(call test_bin_cmd_exit_code, $(CDT_ZIG_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_ZIG_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.ct,1)
	$(call test_bin_cmd_exit_code, $(CDT_ZIG_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/valid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_ZIG_BIN), file-has-header, $(CDT_TESTDATA_DIR)/v1/valid-header-minimal.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_ZIG_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/invalid-header-full-featured.cdt,1)
	$(call test_bin_cmd_exit_code, $(CDT_ZIG_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/valid-header-full-featured.cdt,0)
	$(call test_bin_cmd_exit_code, $(CDT_ZIG_BIN), file-has-valid-header, $(CDT_TESTDATA_DIR)/v1/valid-header-minimal.cdt,0)
	@echo 'TEST ZIG DONE'

####################
# BENCHMARKS
####################
PHONY += bench
bench:
	$(CDT_BENCH_DIR)/run-benchmarks.py

####################
# SPECS
####################
PHONY += spec-v1-gen-testdata
spec-v1-gen-testdata:
	go generate ./...

####################
# GENERAL
####################
PHONY += clean
clean:
	rm -rf $(CDT_BUILD_DIR)

PHONY += env
env:
	$(foreach VAR,$(sort $(filter CDT_%,$(.VARIABLES))),$(info $(VAR) is $($(VAR))))

PHONY += version
version:
	@echo  'CDT_VERSION_FULL: 		${CDT_VERSION_FULL}'
	@echo  'CDT_VERSION_TAG: 		${CDT_VERSION_TAG}'
	@echo  'CDT_VERSION: 			${CDT_VERSION}'
	@echo  'CDT_VERSION_MAJOR: 		${CDT_VERSION_MAJOR}'
	@echo  'CDT_VERSION_MINOR: 		${CDT_VERSION_MINOR}'
	@echo  'CDT_VERSION_PATCH: 		${CDT_VERSION_PATCH}'
	@echo  'CDT_VERSION_COMMITS_SINCE_TAG: 	${CDT_VERSION_COMMITS_SINCE_TAG}'
	@echo  'CDT_VERSION_COMMIT_SHORT: 	${CDT_VERSION_COMMIT_SHORT}'
	@echo  'CDT_VERSION_COMMIT_LONG: 	${CDT_VERSION_COMMIT_LONG}'

PHONY += FORCE
FORCE:

# Declare the contents of the PHONY variable as phony.  We keep that
# information in a variable so we can use it in if_changed and friends.
.PHONY: $(PHONY)