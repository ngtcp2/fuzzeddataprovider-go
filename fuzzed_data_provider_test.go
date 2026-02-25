package fuzz

import (
	"math"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestConsumeBytes(t *testing.T) {
	fdp := NewFuzzedDataProvider([]byte{0xba, 0xad, 0xf0, 0x0d})

	assert.Equal(t, []byte{0xba, 0xad, 0xf0}, fdp.ConsumeBytes(3))
	assert.Equal(t, []byte{0x0d}, fdp.ConsumeBytes(2))
	assert.Nil(t, fdp.ConsumeBytes(2))
}

func TestRemainingBytes(t *testing.T) {
	b := []byte{0xba, 0xad, 0xf0, 0x0d}
	fdp := NewFuzzedDataProvider(b)

	assert.Equal(t, len(b), fdp.RemainingBytes())

	fdp.ConsumeUint32()

	assert.Equal(t, 0, fdp.RemainingBytes())
}

func TestConsumeRemainingBytes(t *testing.T) {
	b := []byte{0xba, 0xad, 0xf0, 0x0d}
	fdp := NewFuzzedDataProvider(b)

	assert.Equal(t, b, fdp.ConsumeRemainingBytes())
}

func TestConsumeBytesAsString(t *testing.T) {
	fdp := NewFuzzedDataProvider([]byte("foo bar"))

	assert.Equal(t, "foo ", fdp.ConsumeBytesAsString(4))
	assert.Equal(t, "bar", fdp.ConsumeBytesAsString(4))
	assert.Empty(t, fdp.ConsumeBytesAsString(4))
}

func TestConsumeRandomLengthString(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte("foo bar alpha\\\\bravo\\charlie\\"))

	assert.Equal(t, "foo bar alpha\\br", fdp.ConsumeRandomLengthString(16))
	assert.Equal(t, "avo", fdp.ConsumeRandomLengthString(9))
	assert.Equal(t, "harlie\\", fdp.ConsumeRandomLengthString(100))
}

func TestConsumeInt(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	if unsafe.Sizeof(0) == unsafe.Sizeof(uint64(0)) {
		assert.Equal(t, 8052064353013247418, fdp.ConsumeInt())
	} else {
		assert.Equal(t, 1874767326, fdp.ConsumeInt())
		assert.Equal(t, -1913606726, fdp.ConsumeInt())
	}

	assert.Equal(t, math.MinInt, fdp.ConsumeInt())
}

func TestConsumeInt8(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.Equal(t, int8(111), fdp.ConsumeInt8())
	assert.Equal(t, int8(62), fdp.ConsumeInt8())
	assert.Equal(t, int8(45), fdp.ConsumeInt8())
	assert.Equal(t, int8(94), fdp.ConsumeInt8())
	assert.Equal(t, int8(-115), fdp.ConsumeInt8())
	assert.Equal(t, int8(112), fdp.ConsumeInt8())
	assert.Equal(t, int8(45), fdp.ConsumeInt8())
	assert.Equal(t, int8(58), fdp.ConsumeInt8())
	assert.Equal(t, int8(math.MinInt8), fdp.ConsumeInt8())
}

func TestConsumeInt16(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.Equal(t, int16(28606), fdp.ConsumeInt16())
	assert.Equal(t, int16(11742), fdp.ConsumeInt16())
	assert.Equal(t, int16(-29200), fdp.ConsumeInt16())
	assert.Equal(t, int16(11706), fdp.ConsumeInt16())
	assert.Equal(t, int16(math.MinInt16), fdp.ConsumeInt16())
}

func TestConsumeInt32(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.Equal(t, int32(1874767326), fdp.ConsumeInt32())
	assert.Equal(t, int32(-1913606726), fdp.ConsumeInt32())
	assert.Equal(t, int32(math.MinInt32), fdp.ConsumeInt32())
}

func TestConsumeInt64(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.Equal(t, int64(8052064353013247418), fdp.ConsumeInt64())
	assert.Equal(t, int64(math.MinInt64), fdp.ConsumeInt64())
}

func TestConsumeUint(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	if unsafe.Sizeof(0) == unsafe.Sizeof(uint64(0)) {
		assert.Equal(t, uint(0xefbeadde0df0adba), fdp.ConsumeUint())
	} else {
		assert.Equal(t, uint(0xefbeadde), fdp.ConsumeUint())
		assert.Equal(t, uint(0x0df0adba), fdp.ConsumeUint())
	}

	assert.Equal(t, uint(0x00), fdp.ConsumeUint())
}

func TestConsumeUint8(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.Equal(t, uint8(0xef), fdp.ConsumeUint8())
	assert.Equal(t, uint8(0xbe), fdp.ConsumeUint8())
	assert.Equal(t, uint8(0xad), fdp.ConsumeUint8())
	assert.Equal(t, uint8(0xde), fdp.ConsumeUint8())
	assert.Equal(t, uint8(0x0d), fdp.ConsumeUint8())
	assert.Equal(t, uint8(0xf0), fdp.ConsumeUint8())
	assert.Equal(t, uint8(0xad), fdp.ConsumeUint8())
	assert.Equal(t, uint8(0xba), fdp.ConsumeUint8())
	assert.Equal(t, uint8(0x00), fdp.ConsumeUint8())
}

func TestConsumeUint16(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.Equal(t, uint16(0xefbe), fdp.ConsumeUint16())
	assert.Equal(t, uint16(0xadde), fdp.ConsumeUint16())
	assert.Equal(t, uint16(0x0df0), fdp.ConsumeUint16())
	assert.Equal(t, uint16(0xadba), fdp.ConsumeUint16())
	assert.Equal(t, uint16(0x00), fdp.ConsumeUint16())
}

func TestConsumeUint32(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.Equal(t, uint32(0xefbeadde), fdp.ConsumeUint32())
	assert.Equal(t, uint32(0x0df0adba), fdp.ConsumeUint32())
	assert.Equal(t, uint32(0x00), fdp.ConsumeUint32())
}

func TestConsumeUint64(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.Equal(t, uint64(0xefbeadde0df0adba), fdp.ConsumeUint64())
	assert.Equal(t, uint64(0x00), fdp.ConsumeUint64())
}

func TestConsumeInt64InRange(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.Equal(t, int64(380), fdp.ConsumeInt64InRange(-110, 871))
	assert.Equal(t, int64(210), fdp.ConsumeInt64InRange(-110, 871))
	assert.Equal(t, int64(0), fdp.ConsumeInt64InRange(-1, 1))
	assert.Equal(t, int64(-1), fdp.ConsumeInt64InRange(-1, 1))
	assert.Equal(t, int64(-9223372036854731333),
		fdp.ConsumeInt64InRange(-math.MaxInt64, 1))
	assert.Equal(t, int64(-9223372036854775807),
		fdp.ConsumeInt64InRange(-math.MaxInt64, 1))
}

func TestConsumeUint64InRange(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.Equal(t, uint64(0xefbeadde0df0adba),
		fdp.ConsumeUint64InRange(0, math.MaxUint64))
	assert.Equal(t, uint64(0), fdp.ConsumeUint64InRange(0, math.MaxUint64))
}

func TestConsumeFloat32InRange(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.InDelta(t, float32(3.1867554e+38),
		fdp.ConsumeFloat32InRange(
			-math.MaxFloat32+math.MaxFloat32, math.MaxFloat32), 0.0)
	assert.InDelta(t, float32(1.8529638e+37),
		fdp.ConsumeFloat32InRange(
			-math.MaxFloat32+math.MaxFloat32, math.MaxFloat32), 0.0)
	assert.InDelta(t, float32(0),
		fdp.ConsumeFloat32InRange(
			-math.MaxFloat32+math.MaxFloat32, math.MaxFloat32), 0.0)

	fdp = NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.InDelta(t, float32(93.87414),
		fdp.ConsumeFloat32InRange(-0.9, 100.3), 0.0)
	assert.InDelta(t, float32(4.6107163),
		fdp.ConsumeFloat32InRange(-0.9, 100.3), 0.0)
}

func TestConsumeFloat64InRange(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.InDelta(t, 1.6835455230323025e+308,
		fdp.ConsumeFloat64InRange(
			-math.MaxFloat64+math.MaxFloat64, math.MaxFloat64), 0.0)
	assert.InDelta(t, 0.0,
		fdp.ConsumeFloat64InRange(
			-math.MaxFloat64+math.MaxFloat64, math.MaxFloat64), 0.0)

	fdp = NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.InDelta(t, 93.87413226252205,
		fdp.ConsumeFloat64InRange(-0.9, 100.3), 0.0)
	assert.InDelta(t, -0.9, fdp.ConsumeFloat64InRange(-0.9, 100.3), 0.0)
}

func TestConsumeProbabilityFloat32(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.InDelta(t, float32(0.9365033), fdp.ConsumeProbabilityFloat32(),
		0.0)
	assert.InDelta(t, float32(0.054453716), fdp.ConsumeProbabilityFloat32(),
		0.0)
	assert.InDelta(t, float32(0), fdp.ConsumeProbabilityFloat32(), 0.0)
}

func TestConsumeProbabilityFloat64(t *testing.T) {
	fdp := NewFuzzedDataProvider(
		[]byte{0xba, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef})

	assert.InDelta(t, 0.9365032832265026, fdp.ConsumeProbabilityFloat64(),
		0.0)
	assert.InDelta(t, 0.0, fdp.ConsumeProbabilityFloat64(), 0.0)
}

func TestConsumeBool(t *testing.T) {
	fdp := NewFuzzedDataProvider([]byte{0xba, 0xad, 0xf0, 0x0d})

	assert.True(t, fdp.ConsumeBool())
	assert.False(t, fdp.ConsumeBool())
	assert.True(t, fdp.ConsumeBool())
	assert.False(t, fdp.ConsumeBool())
	assert.False(t, fdp.ConsumeBool())
}
