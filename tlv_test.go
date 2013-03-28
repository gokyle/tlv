package tlv

import "fmt"
import "io/ioutil"
import "os"
import "testing"

const (
	TagTest1 = iota
	TagTest2
	TagTest3
	TagTest4
	TagTest5
	TagTest6
)

func FailWithError(t *testing.T, name string, err error) {
	fmt.Printf("[!] %s failed: %s\n", name, err.Error())
	t.FailNow()
}

var noMatch = fmt.Errorf("TLV records don't match")

func TestTLVRead(t *testing.T) {
	descr := []byte("This is a test description.")
	tlv := newTLV(TagTest1, descr)

	tmpFile, err := ioutil.TempFile("", "metakey_test_")
	if err != nil {
		FailWithError(t, "TestTLVRead", err)
	}
	tmpName := tmpFile.Name()
	err = writeRecord(tlv, tmpFile)
	if err != nil {
		FailWithError(t, "TestTLVRead", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpName)

	tlvRaw, err := ioutil.ReadFile(tmpName)
	if err != nil {
		FailWithError(t, "TestTLVRead", err)
	}
	tmpTLV, err := tlvFromBytes(tlvRaw)
	if err != nil {
		FailWithError(t, "TestTLVRead", err)
	}

	if !Equals(tlv, tmpTLV) {
		FailWithError(t, "TestTLVRead", noMatch)
	}

	tmpFile, err = os.Open(tmpName)
	if err != nil {
		FailWithError(t, "TestTLVRead", err)
	}
	tmpTLV, err = readRecord(tmpFile)
	if err != nil {
		FailWithError(t, "TestTLVRead", err)
	} else if !Equals(tlv, tmpTLV) {
		FailWithError(t, "TestTLVRead", noMatch)
	}

}

func TestTLVListAdd(t *testing.T) {
	tlvl := New()

	tlv1 := newTLV(TagTest1, []byte("foo bar"))
	tlv2 := newTLV(TagTest2, []byte("baz quux"))
	tlvl.Add(TagTest1, []byte("foo bar"))
	tlvl.Add(TagTest2, []byte("baz quux"))

	if tlvl.Length() != 2 {
		err := fmt.Errorf("records not added")
		FailWithError(t, "TestTLVListAdd", err)
	}

	tmpTLV, err := tlvl.Get(TagTest1)
	if err != nil {
		FailWithError(t, "TestTLVListAdd", noMatch)
	} else if !Equals(tmpTLV, tlv1) {
		FailWithError(t, "TestTLVListAdd", noMatch)
	}

	tmpTLV, err = tlvl.Get(TagTest2)
	if err != nil {
		FailWithError(t, "TestTLVListAdd", noMatch)
	} else if !Equals(tmpTLV, tlv2) {
		FailWithError(t, "TestTLVListAdd", noMatch)
	}
}

func TestTLVListRemove(t *testing.T) {
	tlvl := New()
	tlvl.Add(TagTest1, []byte("foo bar"))

	if tlvl.Length() != 1 {
		err := fmt.Errorf("records not added")
		FailWithError(t, "TestTLVListAdd", err)
	}

	if 1 != tlvl.Remove(TagTest1) {
		FailWithError(t, "TestTLVListRemove",
			fmt.Errorf("record not removed"))
	}

	if _, err := tlvl.Get(TagTest1); err != ErrTagNotFound {
		FailWithError(t, "TestTLVListRemove",
			fmt.Errorf("record should be removed"))
	}
}

func TestTLVListRemoveRecord(t *testing.T) {
	tlvl := New()
	tlv1 := newTLV(TagTest1, []byte("foo bar"))
	tlvl.Add(TagTest1, []byte("foo bar"))

	if tlvl.Length() != 1 {
		err := fmt.Errorf("records not added")
		FailWithError(t, "TestTLVListAdd", err)
	}

	if 1 != tlvl.RemoveRecord(tlv1) {
		FailWithError(t, "TestTLVListRemove",
			fmt.Errorf("record not removed"))
	}

	if _, err := tlvl.Get(TagTest1); err != ErrTagNotFound {
		FailWithError(t, "TestTLVListRemove",
			fmt.Errorf("record should be removed"))
	}
}

func TestTLVListRemoveRecords(t *testing.T) {
	tlvl := New()
	tlv1 := newTLV(TagTest1, []byte("foo bar"))
	tlv2 := newTLV(TagTest2, []byte("baz quux"))
	tlv3 := newTLV(TagTest1, []byte("goodbye, cruel world"))
	tlvl.AddRecord(tlv1)
	tlvl.AddRecord(tlv2)
	tlvl.AddRecord(tlv3)

	if tlvl.Length() != 3 {
		err := fmt.Errorf("records not added")
		FailWithError(t, "TestTLVRemoveRecords", err)
	}

        if tlvs := tlvl.GetAll(TagTest1); len(tlvs) != 2 {
                fmt.Printf("%d TagTest1 records, expected %d\n",
                        len(tlvs), 2)
                FailWithError(t, "TestTLVListRemoveRecords",
                        fmt.Errorf("records not added"))
        }

	if n := tlvl.Remove(TagTest1); n != 2 {
                fmt.Printf("only %d records removed\n", n)
		FailWithError(t, "TestTLVListRemoveRecords",
			fmt.Errorf("record not removed"))
	}

	if _, err := tlvl.Get(TagTest1); err != ErrTagNotFound {
		FailWithError(t, "TestTLVListRemove",
			fmt.Errorf("record should be removed"))
	}
}

func TestTLVListReadWrite(t *testing.T) {
	tlvl := New()

	tlv1 := newTLV(TagTest1, []byte("foo bar"))
	tlv2 := newTLV(TagTest2, []byte("baz quux"))
	tlv3 := newTLV(TagTest3, []byte("gophers are everywhere!"))
	tlv4 := newTLV(TagTest4, []byte{53, 139, 142, 31, 142, 157, 225, 31,
		13, 253, 8, 22, 204, 168, 197, 37,
		102, 99, 63, 217, 89, 167, 63, 120,
		219, 154, 148, 175, 195, 24, 35, 55})
	tlv5 := newTLV(TagTest5, []byte{79, 74, 170, 235, 57, 206, 46, 164,
		152, 26, 5, 55, 128, 176, 50, 93, 219,
		190, 120, 11, 11, 172, 145, 81, 153,
		174, 192, 120, 56, 207, 84, 180, 71,
		252, 199, 98, 13, 142, 149, 150, 159,
		80, 9, 239, 5, 36, 50, 82, 128, 216,
		217, 247, 180, 53, 215, 187, 101, 78,
		124, 79, 201, 36, 200, 55})
	tlv6 := newTLV(TagTest6, []byte{61, 138, 6, 151, 196, 225, 46, 32, 31,
		227, 35, 47, 85, 196, 155, 82, 98,
		113, 221, 48, 119, 34, 126, 70, 183,
		222, 185, 125, 65, 249, 167, 101, 98,
		182, 112, 159, 3, 139, 66, 104, 55,
		108, 161, 146, 175, 89, 70, 97, 70,
		168, 83, 95, 217, 179, 28, 35, 168,
		115, 101, 123, 222, 60, 175, 185, 171,
		166, 192, 74, 131, 105, 235, 245, 102,
		245, 176, 113, 10, 148, 176, 216, 174,
		72, 138, 159, 238, 133, 239, 0, 18,
		221, 96, 20, 216, 63, 77, 246, 85, 248,
		169, 230, 234, 48, 80, 175, 225, 175,
		109, 95, 192, 127, 215, 110, 30, 69,
		186, 205, 50, 207, 228, 168, 13, 186,
		104, 73, 142, 158, 114, 152})
	tlvs := []TLV{tlv1, tlv2, tlv3, tlv4, tlv5, tlv6}

	tlvl.Add(tlv1.Tag(), tlv1.Value())
	tlvl.Add(tlv2.Tag(), tlv2.Value())
	tlvl.Add(tlv3.Tag(), tlv3.Value())
	tlvl.Add(tlv4.Tag(), tlv4.Value())
	tlvl.Add(tlv5.Tag(), tlv5.Value())
	tlvl.Add(tlv6.Tag(), tlv6.Value())

	tmpFile, err := ioutil.TempFile("", "metakey_test_")
	if err != nil {
		FailWithError(t, "TestTLVListReadWrite", err)
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	err = tlvl.Write(tmpFile)
	if err != nil {
		FailWithError(t, "TestTLVListReadWrite", err)
	}
	tmpFile.Close()

	tmpFile, err = os.Open(tmpName)
	if err != nil {
		FailWithError(t, "TestTLVListReadWrite", err)
	}

	rtlvl, err := Read(tmpFile)
	if err != nil {
		FailWithError(t, "TestTLVListReadWrite", err)
	}

	for _, testTLV := range tlvs {
		rTLV, err := rtlvl.Get(testTLV.Tag())
		if err != nil {
			FailWithError(t, "TestTLVListReadWrite", err)
		} else if !Equals(testTLV, rTLV) {
			FailWithError(t, "TestTLVListReadWrite", noMatch)
		}
	}
}
