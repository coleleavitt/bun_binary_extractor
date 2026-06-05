# bun_binary_extractor

Extract embedded files from Bun standalone executables.

## Coverage Targets

The unit tests build small in-memory standalone graphs for the parser cases that are easy to regress:

- Legacy appended payloads with 36-byte module records.
- Modern 52-byte records with bytecode, module_info, bytecode_origin_path, and loaders up to `md`.
- PE `.bun`, ELF `.bun`, and Mach-O `__BUN,__bun` section containers.
- Unix and Windows Bun virtual paths.
- Sourcemap source paths containing Bun virtual `../node_modules` traversals.

For real fixture binaries, generate a matrix with a current Bun build:

```sh
bun build entry.js --compile --outfile fixtures/linux-basic
bun build entry.js --compile --sourcemap --outfile fixtures/linux-sourcemap
bun build entry.js --compile --bytecode --format=esm --outfile fixtures/linux-bytecode-esm
bun build entry.js --compile --target=bun-windows-x64 --outfile fixtures/windows.exe
bun build entry.js --compile --target=bun-darwin-arm64 --outfile fixtures/darwin-arm64
```

Useful fixture entrypoints:

- JS/TS entry with `--sourcemap`.
- ESM entry with dynamic import and `--bytecode` to produce per-module bytecode and module_info.
- Asset imports that show up through `Bun.embeddedFiles`.
- JSON5, Markdown, WASM, N-API, and file-loader assets to cover loader tags.

## Bun Dump-Code Workflow

Bun canary/debug builds include `BUN_FEATURE_FLAG_DUMP_CODE` in `StandaloneModuleGraph` serialization. Set it while compiling fixtures to dump the generated standalone graph code before it is embedded:

```sh
BUN_FEATURE_FLAG_DUMP_CODE=/tmp/bun-dump bun build entry.js --compile --sourcemap --bytecode --outfile app
```

This does not recover anything extra from third-party release binaries, but it gives a ground-truth directory for comparing extractor output against Bun's own serializer.

## Bytecode

`--extract-bytecode` writes Bun/JSC bytecode blobs as raw `.bytecode` files. The executable still embeds the generated JavaScript contents separately, so source recovery does not require bytecode disassembly. Interpreting or decompiling JSC bytecode is intentionally out of scope for this extractor.

## Sourcemap Source Provenance

`--decode-sourcemaps` writes each decoded sourcemap as standard JSON and expands its `sourcesContent` entries into a sibling `sources/` directory. These files are whatever Bun embedded in the sourcemap; they are not guaranteed to be pristine authoring sources.

Some build pipelines put post-transform code in `sourcesContent`. For example, a `.tsx` source may contain Solid/OpenTUI helper symbols such as `_$insert`, `_$createComponent`, or `_$memo` if the sourcemap was generated after JSX compilation.

For OpenTUI/Solid universal JSX output, the extractor now writes best-effort recovered TSX into a sibling `sources-recovered/` directory. This is a readability aid, not a lossless inverse compiler. It keeps the raw `sources/` file as the authoritative artifact and records recovery metadata in the manifest. Pass `--no-decompile-sources` to skip recovered-source sidecars.

To make this explicit, each `sources/` directory also gets a `source-manifest.json` file. The manifest records:

- original sourcemap source path
- sanitized output path
- content byte length
- FNV-1a content hash
- `provenance: "sourcemap.sourcesContent"`
- `likely_transformed`
- transform-signal reasons when obvious compiler or bundler helper patterns are present
- optional recovered source output under `sources-recovered/`
- recovery warnings when a transformed construct could not be converted cleanly
- skipped entries, such as filtered or unsafe paths

Treat `likely_transformed` as a triage signal, not proof. The authoritative fact is that the recovered file came from sourcemap `sourcesContent`.
