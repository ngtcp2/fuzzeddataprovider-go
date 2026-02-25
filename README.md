# fuzzeddataprovider-go

`fuzzeddataprovider-go` is a Go port of LLVM's
[FuzzedDataProvider.h](https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h).

It provides a simple utility to split a raw blob of fuzzing data
(e.g., from `go test -fuzz`) into various primitive types, making it
easier to fuzz APIs that require structured input.

## Features

- **Idiomatic Go API**: Ported specifically for Go workflows while
  maintaining the logic of the LLVM original.
- **Safety**: Automatically handles bounds checking.  If you request
  more data than available, it returns the remaining data or
  zero-values.
- **Deterministic**: Ensures that the same input bytes always produce
  the same structured output.

## Installation

```bash
go get github.com/ngtcp2/fuzzeddataprovider-go
```

## Usage

```go
package fuzz_test

import (
	"testing"

	"github.com/ngtcp2/fuzzeddataprovider-go"
)

func FuzzYourAPI(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Initialize the provider
		fdp := fuzz.NewFuzzedDataProvider(data)

		// Consume data as different types
		count := fdp.ConsumeUint32()
		name  := fdp.ConsumeRandomLengthString(255)
		payload := fdp.ConsumeBytes(1024)

		// Use the structured data to test your code
		YourAPI(count, name, payload)
	})
}
```

See also https://pkg.go.dev/github.com/ngtcp2/fuzzeddataprovider-go

## Why use this instead of manually slicing `[]byte`?

Manually slicing the data byte slice in a fuzz target is error-prone
and often leads to "out of bounds" panics that are bugs in the test
itself rather than the code being tested.  FuzzedDataProvider
abstracts this away, ensuring your fuzz target remains robust and
readable.

## License

The MIT License

Copyright (c) 2026 fuzzeddataprovider-go contributors
