package framing

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"sync"
)

// MaxFrameSize is the default maximum frame size (10 MB).
const MaxFrameSize = 10 * 1024 * 1024

// Framer provides per-instance configurable frame size limits. (C2)
type Framer struct {
	// MaxFrameSize overrides the package-level constant if > 0.
	MaxFrameSize uint32
}

// NewFramer creates a Framer with the given per-instance max frame size. (C2)
func NewFramer(maxFrameSize uint32) *Framer {
	if maxFrameSize == 0 {
		maxFrameSize = MaxFrameSize
	}
	return &Framer{MaxFrameSize: maxFrameSize}
}

// WriteFrame writes a length-prefixed frame using this framer's settings.
func (f *Framer) WriteFrame(w io.Writer, data []byte) error {
	return WriteFrame(w, data)
}

// ReadFrame reads a length-prefixed frame, enforcing this framer's MaxFrameSize.
func (f *Framer) ReadFrame(r io.Reader) ([]byte, error) {
	hp := headerPool.Get().(*[]byte)
	h := *hp
	defer headerPool.Put(hp)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(h)
	limit := f.MaxFrameSize
	if limit == 0 {
		limit = MaxFrameSize
	}
	if size > limit {
		return nil, fmt.Errorf("frame size %d exceeds maximum %d", size, limit)
	}
	if size <= 65536 {
		bp := bufPool.Get().(*[]byte)
		buf := (*bp)[:size]
		if _, err := io.ReadFull(r, buf); err != nil {
			bufPool.Put(bp)
			return nil, err
		}
		result := make([]byte, size)
		copy(result, buf)
		bufPool.Put(bp)
		return result, nil
	}
	buf := make([]byte, size)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// M5: Buffer pools for header and payload buffers
var headerPool = sync.Pool{New: func() interface{} { b := make([]byte, 4); return &b }}
var bufPool = sync.Pool{New: func() interface{} { b := make([]byte, 65536); return &b }}

func WriteFrame(w io.Writer, data []byte) error {
	hp := headerPool.Get().(*[]byte)
	h := *hp
	defer headerPool.Put(hp)
	binary.BigEndian.PutUint32(h, uint32(len(data)))
	if _, err := w.Write(h); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func ReadFrame(r io.Reader) ([]byte, error) {
	hp := headerPool.Get().(*[]byte)
	h := *hp
	defer headerPool.Put(hp)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(h)
	if size > MaxFrameSize {
		return nil, fmt.Errorf("frame size %d exceeds maximum %d", size, MaxFrameSize)
	}
	if size <= 65536 {
		bp := bufPool.Get().(*[]byte)
		buf := (*bp)[:size]
		if _, err := io.ReadFull(r, buf); err != nil {
			bufPool.Put(bp)
			return nil, err
		}
		result := make([]byte, size)
		copy(result, buf)
		bufPool.Put(bp)
		return result, nil
	}
	buf := make([]byte, size)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// L5: FramerOptions for optional CRC32 checksum
type FramerOptions struct {
	WithChecksum bool
}

// WriteFrameWithOptions writes a frame with optional CRC32 checksum. (L5)
func WriteFrameWithOptions(w io.Writer, data []byte, opts FramerOptions) error {
	if !opts.WithChecksum {
		return WriteFrame(w, data)
	}
	// Frame: [4-byte len][data][4-byte CRC32]
	h := make([]byte, 4)
	binary.BigEndian.PutUint32(h, uint32(len(data)))
	if _, err := w.Write(h); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	checksum := crc32.ChecksumIEEE(data)
	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, checksum)
	_, err := w.Write(c)
	return err
}

// ReadFrameWithOptions reads a frame with optional CRC32 checksum. (L5)
func ReadFrameWithOptions(r io.Reader, opts FramerOptions) ([]byte, error) {
	if !opts.WithChecksum {
		return ReadFrame(r)
	}
	// Read [4-byte len][data][4-byte CRC32]
	h := make([]byte, 4)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(h)
	if size > MaxFrameSize {
		return nil, fmt.Errorf("frame size %d exceeds maximum %d", size, MaxFrameSize)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	// Read and verify checksum
	cs := make([]byte, 4)
	if _, err := io.ReadFull(r, cs); err != nil {
		return nil, err
	}
	expected := binary.BigEndian.Uint32(cs)
	actual := crc32.ChecksumIEEE(buf)
	if expected != actual {
		return nil, fmt.Errorf("checksum mismatch: expected %d, got %d", expected, actual)
	}
	return buf, nil
}
