// +build windows

package registry

import (
	"testing"
)

type BasicStruct struct {
	StringValue string
	SmallInt    int8
	SmallUint   uint8
	BigInt      int64
	BigUint     uint64
	Data        []byte
	MultiString []string
}

func TestUnmarshal(t *testing.T) {
	var bs BasicStruct
	err := Parse("//hklm/Software/HowettNET/Test", &bs)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	t.Logf("%+v", bs)
}

type ComplexStruct struct {
	Ess      string
	SubBasic BasicStruct
	BasicStruct
}

func TestNestedUnmarshal(t *testing.T) {
	dec := NewDecoder("//hklm/Software/HowettNET/Test")
	var bs ComplexStruct
	err := dec.Decode(&bs)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	t.Logf("%+v", bs)
}
