package tlv

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"fmt"
	"io"
)

// Type TLV represents a Tag-Length-Value record.
type TLV interface {
	Tag() int
	Length() int
	Value() []byte
}

type record struct {
	tag    int
	length int
	value  []byte
}

// Method Tag returns the record's tag.
func (t *record) Tag() int {
	return t.tag
}

// Method Length returns the record's value's length.
func (t *record) Length() int {
	return t.length
}

// Method Value returns the record's value.
func (t *record) Value() []byte {
	return t.value
}

// Equals returns true if a pair of TLV records are the same.
func Equals(tlv1, tlv2 TLV) bool {
	if tlv1 == nil {
		if tlv2 == nil {
			return true
		}
		return false
	} else if tlv2 == nil {
		return false
	} else if tlv1.Tag() != tlv2.Tag() {
		return false
	} else if tlv1.Length() != tlv2.Length() {
		return false
	} else if !bytes.Equal(tlv1.Value(), tlv2.Value()) {
		return false
	}
	return true
}

// ErrTLVRead is returned when there is an error reading a TLV record;
// similarly, TLVWrite is returned when  there is an error writing a
// TLV record. ErrTagNotFound is returned when a request for a TLV tag
// is made and none can be found.
var (
	ErrTLVRead     = fmt.Errorf("TLV read error")
	ErrTLVWrite    = fmt.Errorf("TLV write error")
	ErrTagNotFound = fmt.Errorf("tag not found")
)

func newTLV(tag int, value []byte) TLV {
	tlv := new(record)
	tlv.tag = tag
	tlv.length = len(value)
	tlv.value = make([]byte, tlv.Length())
	copy(tlv.value, value)
	return tlv
}

func tlvFromBytes(rec []byte) (tlv TLV, err error) {
	recBuf := bytes.NewBuffer(rec)
	return readRecord(recBuf)
}

func readRecord(r io.Reader) (rec TLV, err error) {
	tlv := new(record)

	var n int32
	err = binary.Read(r, binary.LittleEndian, &n)
	if err != nil {
		return
	}
	tlv.tag = int(n)

	err = binary.Read(r, binary.LittleEndian, &n)
	if err != nil {
		return
	}
	tlv.length = int(n)

	tlv.value = make([]byte, tlv.Length())
	l, err := r.Read(tlv.value)
	if err != nil {
		return
	} else if l != tlv.Length() {
		return tlv, ErrTLVWrite
	}
	return tlv, nil
}

func writeRecord(tlv TLV, w io.Writer) (err error) {
	tmp := int32(tlv.Tag())
	err = binary.Write(w, binary.LittleEndian, tmp)
	if err != nil {
		return
	}

	tmp = int32(tlv.Length())
	err = binary.Write(w, binary.LittleEndian, tmp)
	if err != nil {
		return
	}

	n, err := w.Write(tlv.Value())
	if err != nil {
		return
	} else if n != tlv.Length() {
		return ErrTLVWrite
	}
	return
}

// Type TLVList is a doubly-linked list containing TLV records.
type TLVList struct {
	records *list.List
}

// New returns a new, empty TLVList.
func New() *TLVList {
	tl := new(TLVList)
	tl.records = list.New()
	return tl
}

// Length returns the number of records in the TLVList.
func (tl *TLVList) Length() int {
	return tl.records.Len()
}

// Get checks the TLVList for any record matching the tag. It returns the
// first one found. If the tag could not be found, Get returns ErrTagNotFound.
func (recs *TLVList) Get(tag int) (t TLV, err error) {
	for e := recs.records.Front(); e != nil; e = e.Next() {
		if e.Value.(*record).Tag() == tag {
			return e.Value.(*record), nil
		}
	}
	return nil, ErrTagNotFound
}

// GetAll checks the TLVList for all records matching the tag, returning a
// slice containing all matching records. If no record has the requested
// tag, an empty slice is returned.
func (recs *TLVList) GetAll(tag int) (ts []TLV) {
	ts = make([]TLV, 0)
	for e := recs.records.Front(); e != nil; e = e.Next() {
		if e.Value.(*record).Tag() == tag {
			ts = append(ts, e.Value.(TLV))
		}
	}
	return ts
}

// Remove removes all records with the requested tag. It returns a count
// of the number of removed records.
func (recs *TLVList) Remove(tag int) int {
	var totalRemoved int
	for {
		var removed int
		for e := recs.records.Front(); e != nil; e = e.Next() {
			if e.Value.(*record).Tag() == tag {
				recs.records.Remove(e)
				removed++
				break
			}
		}
		if removed == 0 {
			break
		}
		totalRemoved += removed
	}
	return totalRemoved
}

// RemoveRecord takes a record as an argument, and removes all matching
// records. It matches on not just tag, but also the value contained in
// the record.
func (recs *TLVList) RemoveRecord(rec TLV) int {
	var totalRemoved int
	for {
		var removed int
		for e := recs.records.Front(); e != nil; e = e.Next() {
			if Equals(e.Value.(*record), rec) {
				recs.records.Remove(e)
				removed++
				break
			}
		}
		if removed == 0 {
			break
		}
		totalRemoved += removed
	}
	return totalRemoved
}

// Add pushes a new TLV record onto the TLVList. It builds the record from
// its arguments.
func (recs *TLVList) Add(tag int, value []byte) {
	rec := newTLV(tag, value)
	recs.records.PushBack(rec)
}

// AddRecord adds a TLV record onto the TLVList.
func (recs *TLVList) AddRecord(rec TLV) {
	recs.records.PushBack(rec)
}

// Write writes out the TLVList to an io.Writer.
func (recs *TLVList) Write(w io.Writer) (err error) {
	for e := recs.records.Front(); e != nil; e = e.Next() {
		err = writeRecord(e.Value.(TLV), w)
		if err != nil {
			return
		}
	}
	return
}

// Read takes an io.Reader and builds a TLVList from that.
func Read(r io.Reader) (recs *TLVList, err error) {
	recs = New()
	for {
		var tlv TLV
		if tlv, err = readRecord(r); err != nil {
			break
		}
		recs.records.PushBack(tlv)
	}

	if err == io.EOF {
		err = nil
	}
	return
}
