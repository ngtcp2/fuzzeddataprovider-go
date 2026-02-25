# fuzzeddataprovider-go

`fuzzeddataprovider-go` is a Go port of LLVM's
[FuzzedDataProvider.h](https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h).

It provides a simple utility to split a raw blob of fuzzing data
(e.g., from `go test -fuzz`) into various primitive types, making it
easier to fuzz APIs that require structured input.

## Features

- **Idiomatic Go API**: Ported specifically for Go workflows while
  maintaining the logic of the LLVM original.
- **Safety**: Automatically handles bounds checking. If you request
  more data than available, it returns the remaining data or
  zero-values.
- **Deterministic**: Ensures that the same input bytes always produce
  the same structured output.

## Installation

```bash
go get github.com/ngtcp2/fuzzeddataprovider-go
```

## License

The MIT License

Copyright (c) 2026 fuzzeddataprovider-go contributors
