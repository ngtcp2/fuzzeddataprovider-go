package fuzz

import (
	"math"
	"slices"
	"strings"
	"unsafe"
)

type FuzzedDataProvider struct {
	data []byte
}

// NewFuzzedDataProvider returns new FuzzedDataProvider with data.
func NewFuzzedDataProvider(data []byte) *FuzzedDataProvider {
	return &FuzzedDataProvider{
		data: data,
	}
}

// RemainingBytes returns the remaining bytes available for fuzzed
// input.
func (fdp *FuzzedDataProvider) RemainingBytes() int {
	return len(fdp.data)
}

func (fdp *FuzzedDataProvider) advance(n int) {
	fdp.data = fdp.data[n:]
}

// ConsumeBytes returns slice containing the first n bytes of input
// data.  If fewer than n data remain, it returns a shorter slice
// containing all of the data that are left.  It returns a copy of
// input data.
func (fdp *FuzzedDataProvider) ConsumeBytes(n int) []byte {
	n = min(n, len(fdp.data))
	if n == 0 {
		return nil
	}

	res := slices.Clone(fdp.data[:n])
	fdp.advance(n)

	return res
}

// ConsumeRemainingBytes returns slice containing all remaining bytes
// of the input data.  It returns a copy of input data.
func (fdp *FuzzedDataProvider) ConsumeRemainingBytes() []byte {
	return fdp.ConsumeBytes(len(fdp.data))
}

// ConsumeBytesAsString returns string containing n bytes of input
// data.  If fewer than n bytes of data remain, it returns a shorter
// string containing all of the data that are left.
func (fdp *FuzzedDataProvider) ConsumeBytesAsString(n int) string {
	n = min(n, len(fdp.data))
	if n == 0 {
		return ""
	}

	res := string(fdp.data[:n])
	fdp.advance(n)

	return res
}

// ConsumeRandomLengthString returns string of length from 0 to
// maxLength.  When it runs out of input data, it returns what remains
// of the input.  Designed to be more stable with respect to a fuzzer
// inserting characters than just picking a random length and then
// consuming that many bytes.
func (fdp *FuzzedDataProvider) ConsumeRandomLengthString(maxLength int) string {
	var result strings.Builder

	for i := 0; i < maxLength && len(fdp.data) != 0; i++ {
		next := fdp.data[0]
		fdp.advance(1)

		if next == '\\' && len(fdp.data) != 0 {
			next = fdp.data[0]
			fdp.advance(1)

			if next != '\\' {
				break
			}
		}

		result.WriteByte(next)
	}

	return result.String()
}

// ConsumeRemainingRandomLengthString returns string of length from 0
// to remaining bytes.
func (fdp *FuzzedDataProvider) ConsumeRemainingRandomLengthString() string {
	return fdp.ConsumeRandomLengthString(len(fdp.data))
}

type Integral interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

const (
	charBit = 8
)

func consumeIntegralInRange[T Integral](
	fdp *FuzzedDataProvider, minVal, maxVal T,
) T {
	if minVal > maxVal {
		panic("minVal > maxVal")
	}

	r := uint64(maxVal) - uint64(minVal)

	var (
		result uint64
		offset int
	)

	remBytes := len(fdp.data)

	for offset < int(unsafe.Sizeof(minVal)*charBit) && (r>>offset) > 0 &&
		remBytes != 0 {
		remBytes--
		result = (result << charBit) | uint64(fdp.data[remBytes])
		offset += charBit
	}

	fdp.data = fdp.data[:remBytes]

	if r != math.MaxUint64 {
		result = result % (r + 1)
	}

	return T(uint64(minVal) + result)
}

// ConsumeInt returns a number in the range [math.MinInt,
// math.MaxInt].  The value might not be uniformly distributed in the
// given range.  If there is no input data left, it always returns
// math.MinInt.
func (fdp *FuzzedDataProvider) ConsumeInt() int {
	return consumeIntegralInRange(fdp, math.MinInt, math.MaxInt)
}

// ConsumeInt8 returns a number in the range [math.MinInt8,
// math.MaxInt8].  The value might not be uniformly distributed in the
// given range.  If there is no input data left, it always returns
// math.MinInt8.
func (fdp *FuzzedDataProvider) ConsumeInt8() int8 {
	return consumeIntegralInRange(fdp, int8(math.MinInt8),
		int8(math.MaxInt8))
}

// ConsumeInt16 returns a number in the range [math.MinInt16,
// math.MaxInt16].  The value might not be uniformly distributed in
// the given range.  If there is no input data left, it always returns
// math.MinInt16.
func (fdp *FuzzedDataProvider) ConsumeInt16() int16 {
	return consumeIntegralInRange(fdp, int16(math.MinInt16),
		int16(math.MaxInt16))
}

// ConsumeInt32 returns a number in the range [math.MinInt32,
// math.MaxInt32].  The value might not be uniformly distributed in
// the given range.  If there is no input data left, it always returns
// math.MinInt32.
func (fdp *FuzzedDataProvider) ConsumeInt32() int32 {
	return consumeIntegralInRange(fdp, int32(math.MinInt32),
		int32(math.MaxInt32))
}

// ConsumeInt64 returns a number in the range [math.MinInt64,
// math.MaxInt64].  The value might not be uniformly distributed in
// the given range.  If there is no input data left, it always returns
// math.MinInt64.
func (fdp *FuzzedDataProvider) ConsumeInt64() int64 {
	return consumeIntegralInRange(fdp, int64(math.MinInt64),
		int64(math.MaxInt64))
}

// ConsumeUint returns a number in the range [0, math.MaxUint].  The
// value might not be uniformly distributed in the given range.  If
// there is no input data left, it always returns 0.
func (fdp *FuzzedDataProvider) ConsumeUint() uint {
	return consumeIntegralInRange(fdp, uint(0), math.MaxUint)
}

// ConsumeUint8 returns a number in the range [0, math.MaxUint8].  The
// value might not be uniformly distributed in the given range.  If
// there is no input data left, it always returns 0.
func (fdp *FuzzedDataProvider) ConsumeUint8() uint8 {
	return consumeIntegralInRange(fdp, uint8(0), uint8(math.MaxUint8))
}

// ConsumeUint16 returns a number in the range [0, math.MaxUint16].
// The value might not be uniformly distributed in the given range.
// If there is no input data left, it always returns 0.
func (fdp *FuzzedDataProvider) ConsumeUint16() uint16 {
	return consumeIntegralInRange(fdp, uint16(0), uint16(math.MaxUint16))
}

// ConsumeUint32 returns a number in the range [0, math.MaxUint32].
// The value might not be uniformly distributed in the given range.
// If there is no input data left, it always returns 0.
func (fdp *FuzzedDataProvider) ConsumeUint32() uint32 {
	return consumeIntegralInRange(fdp, uint32(0), uint32(math.MaxUint32))
}

// ConsumeUint64 returns a number in the range [0, math.MaxUint64].
// The value might not be uniformly distributed in the given range.
// If there is no input data left, it always returns 0.
func (fdp *FuzzedDataProvider) ConsumeUint64() uint64 {
	return consumeIntegralInRange(fdp, uint64(0), math.MaxUint64)
}

// ConsumeIntInRange returns a number in the range [minVal, maxVal] by
// consuming bytes from the input data.  The value might not be
// uniformly distributed in the given range.  If there is no input
// data left, it always returns minVal.  minVal must be less than or
// equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeIntInRange(
	minVal, maxVal int,
) int {
	return consumeIntegralInRange(fdp, minVal, maxVal)
}

// ConsumeInt8InRange returns a number in the range [minVal, maxVal]
// by consuming bytes from the input data.  The value might not be
// uniformly distributed in the given range.  If there is no input
// data left, it always returns minVal.  minVal must be less than or
// equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeInt8InRange(
	minVal, maxVal int8,
) int8 {
	return consumeIntegralInRange(fdp, minVal, maxVal)
}

// ConsumeInt16InRange returns a number in the range [minVal, maxVal]
// by consuming bytes from the input data.  The value might not be
// uniformly distributed in the given range.  If there is no input
// data left, it always returns minVal.  minVal must be less than or
// equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeInt16InRange(
	minVal, maxVal int16,
) int16 {
	return consumeIntegralInRange(fdp, minVal, maxVal)
}

// ConsumeInt32InRange returns a number in the range [minVal, maxVal]
// by consuming bytes from the input data.  The value might not be
// uniformly distributed in the given range.  If there is no input
// data left, it always returns minVal.  minVal must be less than or
// equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeInt32InRange(
	minVal, maxVal int32,
) int32 {
	return consumeIntegralInRange(fdp, minVal, maxVal)
}

// ConsumeInt64InRange returns a number in the range [minVal, maxVal]
// by consuming bytes from the input data.  The value might not be
// uniformly distributed in the given range.  If there is no input
// data left, it always returns minVal.  minVal must be less than or
// equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeInt64InRange(
	minVal, maxVal int64,
) int64 {
	return consumeIntegralInRange(fdp, minVal, maxVal)
}

// ConsumeUintInRange returns a number in the range [minVal, maxVal]
// by consuming bytes from the input data.  The value might not be
// uniformly distributed in the given range.  If there is no input
// data left, it always returns minVal.  minVal must be less than or
// equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeUintInRange(
	minVal, maxVal uint,
) uint {
	return consumeIntegralInRange(fdp, minVal, maxVal)
}

// ConsumeUint8InRange returns a number in the range [minVal, maxVal]
// by consuming bytes from the input data.  The value might not be
// uniformly distributed in the given range.  If there is no input
// data left, it always returns minVal.  minVal must be less than or
// equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeUint8InRange(
	minVal, maxVal uint8,
) uint8 {
	return consumeIntegralInRange(fdp, minVal, maxVal)
}

// ConsumeUint16InRange returns a number in the range [minVal, maxVal]
// by consuming bytes from the input data.  The value might not be
// uniformly distributed in the given range.  If there is no input
// data left, it always returns minVal.  minVal must be less than or
// equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeUint16InRange(
	minVal, maxVal uint16,
) uint16 {
	return consumeIntegralInRange(fdp, minVal, maxVal)
}

// ConsumeUint32InRange returns a number in the range [minVal, maxVal]
// by consuming bytes from the input data.  The value might not be
// uniformly distributed in the given range.  If there is no input
// data left, it always returns minVal.  minVal must be less than or
// equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeUint32InRange(
	minVal, maxVal uint32,
) uint32 {
	return consumeIntegralInRange(fdp, minVal, maxVal)
}

// ConsumeUint64InRange returns a number in the range [minVal, maxVal]
// by consuming bytes from the input data.  The value might not be
// uniformly distributed in the given range.  If there is no input
// data left, it always returns minVal.  minVal must be less than or
// equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeUint64InRange(
	minVal, maxVal uint64,
) uint64 {
	return consumeIntegralInRange(fdp, minVal, maxVal)
}

type FloatingPoint interface {
	~float32 | ~float64
}

func consumeFloatingPointInRange[T FloatingPoint](
	fdp *FuzzedDataProvider, minVal, maxVal, limMax T,
) T {
	if minVal > maxVal {
		panic("minVal > maxVal")
	}

	var (
		r    T
		zero T
	)

	result := minVal

	if maxVal > zero && minVal < zero && maxVal > minVal+limMax {
		r = (maxVal / 2.0) - (minVal / 2.0)
		if fdp.ConsumeBool() {
			result += r
		}
	} else {
		r = maxVal - minVal
	}

	return result + r*consumeProbability[T](fdp)
}

// ConsumeFloat32 returns a floating point value in the range
// [-math.MaxFloat32, math.maxFloat32] by consuming bytes from the
// input data.  If there is no input data left, it always returns
// approximately 0.
func (fdp *FuzzedDataProvider) ConsumeFloat32() float32 {
	return consumeFloatingPointInRange(fdp, float32(-math.MaxFloat32),
		float32(math.MaxFloat32), float32(math.MaxFloat32))
}

// ConsumeFloat64 returns a floating point value in the range
// [-math.MaxFloat64, math.maxFloat64] by consuming bytes from the
// input data.  If there is no input data left, it always returns
// approximately 0.
func (fdp *FuzzedDataProvider) ConsumeFloat64() float64 {
	return consumeFloatingPointInRange(fdp, -math.MaxFloat64,
		math.MaxFloat64, math.MaxFloat64)
}

// ConsumeFloat32InRange returns a floating point value in the range
// [minVal, maxVal] by consuming bytes from the input data.  If there
// is no input data left, it returns minVal.  Note that minVal must be
// less than or equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeFloat32InRange(
	minVal, maxVal float32,
) float32 {
	return consumeFloatingPointInRange(fdp, minVal, maxVal,
		float32(math.MaxFloat32))
}

// ConsumeFloat64InRange returns a floating point value in the range
// [minVal, maxVal] by consuming bytes from the input data.  If there
// is no input data left, it returns minVal.  Note that minVal must be
// less than or equal to maxVal.
func (fdp *FuzzedDataProvider) ConsumeFloat64InRange(
	minVal, maxVal float64,
) float64 {
	return consumeFloatingPointInRange(fdp, minVal, maxVal, math.MaxFloat64)
}

func consumeProbability[T FloatingPoint](fdp *FuzzedDataProvider) T {
	if unsafe.Sizeof(T(0)) <= unsafe.Sizeof(uint32(0)) {
		return T(fdp.ConsumeUint32()) / T(math.MaxUint32)
	}

	return T(fdp.ConsumeUint64()) / T(uint64(math.MaxUint64))
}

// ConsumeProbabilityFloat32 returns a floating point value in the
// range [0.0, 1.0].  If there is no input data left, always returns
// 0.
func (fdp *FuzzedDataProvider) ConsumeProbabilityFloat32() float32 {
	return consumeProbability[float32](fdp)
}

// ConsumeProbabilityFloat64 returns a floating point value in the
// range [0.0, 1.0].  If there is no input data left, always returns
// 0.
func (fdp *FuzzedDataProvider) ConsumeProbabilityFloat64() float64 {
	return consumeProbability[float64](fdp)
}

// ConsumeBool reads one byte and returns a bool, or false when no
// data remains.
func (fdp *FuzzedDataProvider) ConsumeBool() bool {
	return 1&fdp.ConsumeUint8() != 0
}
