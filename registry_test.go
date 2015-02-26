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
	err := Parse("HKLM", `Software\HowettNET\Test`, &bs)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	t.Logf("%+v", bs)
}
