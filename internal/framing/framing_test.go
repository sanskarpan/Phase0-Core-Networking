package framing

import (
	"bytes"
	"testing"
)

// =============================================================================
// M5: Buffer Pool Tests
// =============================================================================

func TestFramingRoundTrip(t *testing.T) {
	data := []byte("hello framing")
	var buf bytes.Buffer

	if err := WriteFrame(&buf, data); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Errorf("round-trip mismatch: got %q want %q", got, data)
	}
}

func TestFramingBufferPool(t *testing.T) {
	// Use the pool repeatedly to verify pooled buffers don't corrupt data.
	for i := 0; i < 100; i++ {
		payload := bytes.Repeat([]byte{byte(i % 256)}, 1024)
		var buf bytes.Buffer

		if err := WriteFrame(&buf, payload); err != nil {
			t.Fatalf("WriteFrame iter %d failed: %v", i, err)
		}

		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame iter %d failed: %v", i, err)
		}

		if !bytes.Equal(got, payload) {
			t.Errorf("iter %d: data corrupted by pool reuse", i)
		}
	}
}

// =============================================================================
// L5: CRC32 Checksum Tests
// =============================================================================

func TestFramingChecksum(t *testing.T) {
	data := []byte("checksum test payload")
	opts := FramerOptions{WithChecksum: true}
	var buf bytes.Buffer

	if err := WriteFrameWithOptions(&buf, data, opts); err != nil {
		t.Fatalf("WriteFrameWithOptions failed: %v", err)
	}

	got, err := ReadFrameWithOptions(&buf, opts)
	if err != nil {
		t.Fatalf("ReadFrameWithOptions failed: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Errorf("checksum round-trip mismatch: got %q want %q", got, data)
	}
}

func TestFramingChecksumTampered(t *testing.T) {
	data := []byte("tamper me")
	opts := FramerOptions{WithChecksum: true}
	var buf bytes.Buffer

	if err := WriteFrameWithOptions(&buf, data, opts); err != nil {
		t.Fatalf("WriteFrameWithOptions failed: %v", err)
	}

	// Tamper with the payload byte
	raw := buf.Bytes()
	raw[5] ^= 0xFF // flip a bit in the payload

	tampered := bytes.NewReader(raw)
	_, err := ReadFrameWithOptions(tampered, opts)
	if err == nil {
		t.Error("Expected checksum error for tampered frame")
	}
}

func TestFramingNoChecksum(t *testing.T) {
	data := []byte("no checksum")
	opts := FramerOptions{WithChecksum: false}
	var buf bytes.Buffer

	if err := WriteFrameWithOptions(&buf, data, opts); err != nil {
		t.Fatalf("WriteFrameWithOptions failed: %v", err)
	}

	got, err := ReadFrameWithOptions(&buf, opts)
	if err != nil {
		t.Fatalf("ReadFrameWithOptions failed: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Errorf("no-checksum round-trip mismatch: got %q want %q", got, data)
	}
}
