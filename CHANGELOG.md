# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/outslept/lazypath/releases/tag/v0.1.0) - 2026-11-26

### Added

- *(cli)* reject swallowed flags and conflicting modes and add CI/dry-run options
- *(snapshot)* add atomic writes, %LOCALAPPDATA% paths, import diff/rollback, and elevation state
- *(model)* track registry value types and harden variable validation
- *(ui)* wire interactive tui terminal event loop in main
- *(ui)* build minimalist dual-pane variables list, path priority table, and conflict bar
- *(app)* wire keyboard handlers, executable inspector modal, and registry save
- *(app)* add path priority reordering, dead path sanitizer, and entry crud
- *(app)* implement core state machine, variable list, and dual-pane navigation
- *(cli)* wire one-shot audit, binary lookup, json report, and snapshot cli in main
- *(cli)* implement command-line parser for audit, which, and snapshot modes
- *(snapshot)* implement json environment snapshot export and restore
- *(registry)* add registry writer, setting change broadcaster, and uac elevation
- *(registry)* implement windows registry environment reader and parser
- *(audit)* add binary shadowing detector and which resolver across path
- *(audit)* implement directory executable scanner and path entry builder
- *(expand)* implement windows environment variable expansion and path normalization
- *(model)* add path entry audit structures and shadow conflict descriptors
- *(model)* define environment scopes, variables, and path status types

### Changed

- *(main)* guard terminal raw mode with RAII drop
- *(audit)* replace 5-tuple conflict record with struct and avoid cloning non-conflicting paths
- *(registry)* extract registry type constants and document errors
- *(cli)* deduplicate flag value validation and add rustdoc comments
- *(expand)* remove unused peekable adapter and add rustdoc comments
- *(model)* add rustdoc comments and must_use attributes on pure accessors

### Documentation

- *(snapshot)* add module and item rustdoc with error sections
- *(readme)* update readme
- *(readme)* add readme describing the project

### Fixed

- *(ui)* render confirm-quit dialog, duplicate counters, and expanded variable paths
- *(main)* add panic hook, non-zero check exit codes, and safe snapshot imports
- *(app)* enforce pre-save backups, transactional rollback, quit confirmation, and elevation handoff
- *(audit)* detect WindowsApps reparse aliases, cache directory scans, and honor PATHEXT
- *(registry)* use native UTF-16 Win32 APIs and propagate read/broadcast errors
- *(expand)* support quoted semicolons, recursive expansion, and unicode paths

### Internal

- add concurrency block, take tag & version from fromJSON(steps.rp.outputs.releases)[0]
- add suppress-deprecation-warnings: msystem-mingw64
- fix repo_url
- release v0.1.0 ([#5](https://github.com/outslept/lazypath/pull/5))
- *(deps)* bump anyhow from 1.0.104 to 1.0.105 in the cargo group ([#3](https://github.com/outslept/lazypath/pull/3))
- update README
- fix binary names
- *(deps)* bump actions/upload-artifact from 4.6.2 to 7.0.2 ([#1](https://github.com/outslept/lazypath/pull/1))
- fix clippy warnings
- add gitattributes
- make Rust code 2021 compliant
- setup release-plz
- remove msrv
- add missing HashMap import
- configuration config toml more
- add depedanbot configuration
- add ci workflow
- add MIT license
- *(config)* add rust toolchain, cargo aliases, linter rules, and editorconfig
- initialize cargo package

### Other

- Merge pull request #2 from outslept/dependabot/github_actions/actions/checkout-7.0.1

### Performance

- *(ui)* borrow string slices in widgets instead of cloning per frame
- *(app)* eliminate modal cloning on key events and zero-alloc case-insensitive filtering
