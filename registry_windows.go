// +build windows

package registry

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
)

type fieldInfo struct {
	name      string
	required  bool
	index     []int
	anonymous bool
}

func fieldToFieldInfo(field reflect.StructField) *fieldInfo {
	if field.PkgPath != "" {
		return nil // non-exported fields begone!
	}

	tag := field.Tag.Get("registry")
	if tag == "-" {
		return nil
	}
	sp := strings.Split(tag, ",")
	fi := &fieldInfo{index: field.Index}
	fi.name = sp[0]
	if fi.name == "" {
		fi.name = field.Name
	}

	for _, component := range sp[1:] {
		if component == "required" {
			fi.required = true
		}
	}
	fi.anonymous = field.Anonymous
	return fi
}

type registryEntry interface {
	unmarshal(reflect.Value) error
	fieldInfo() *fieldInfo
	populate(syscall.Handle) error
}

type registryValue struct {
	parent syscall.Handle

	field *fieldInfo

	data []byte
	kind int // syscall.REG_DWORD, etc.
	skip bool
}

func (rv *registryValue) fieldInfo() *fieldInfo {
	return rv.field
}

type registryKey struct {
	parent syscall.Handle
	hkey   syscall.Handle

	field *fieldInfo
	path  string

	skip bool

	subentries []registryEntry
}

func (rk *registryKey) fieldInfo() *fieldInfo {
	return rk.field
}

func Parse(u string, i interface{}) error {
	rval := reflect.ValueOf(i)
	if (rval.Kind() == reflect.Ptr && rval.Type().Elem().Kind() != reflect.Struct) &&
		(rval.Kind() != reflect.Struct) {
		return errors.New("registry: cannot unmarshal into non-struct")
	}

	regUrl, err := url.Parse(u)
	if err != nil {
		return err
	}

	rootHkey := syscall.Handle(0)
	switch strings.ToLower(regUrl.Host) {
	case "hkcu":
		rootHkey = syscall.HKEY_CURRENT_USER
	case "hklm":
		rootHkey = syscall.HKEY_LOCAL_MACHINE
	default:
		return fmt.Errorf("registry: unknown root key '%s'", regUrl.Host)
	}

	path := strings.Replace(regUrl.Path[1:], "/", `\`, -1)
	ent := entryFor(rval.Type(), path, &fieldInfo{required: true})
	err = ent.populate(rootHkey)
	if err != nil {
		return err
	}

	err = ent.unmarshal(rval)
	if err != nil {
		return err
	}

	return nil
}

func entryFor(typ reflect.Type, path string, fi *fieldInfo) registryEntry {
	if fi == nil {
		fi = &fieldInfo{}
	}
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	if typ.Kind() == reflect.Struct {
		subentries := make([]registryEntry, 0, 16)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			newFi := fieldToFieldInfo(field)
			if newFi == nil {
				continue
			}
			subentries = append(subentries, entryFor(typ.Field(i).Type, newFi.name, newFi))
		}
		return &registryKey{
			field:      fi,
			path:       path,
			subentries: subentries,
		}
	} else {
		return &registryValue{
			field: fi,
			kind:  -1,
		}
	}
}

func (rk *registryKey) populate(parent syscall.Handle) error {
	if !rk.field.anonymous {
		pathU16, err := syscall.UTF16PtrFromString(rk.path)
		if err != nil {
			panic(err)
		}

		err = syscall.RegOpenKeyEx(parent, pathU16, 0, syscall.KEY_READ, &rk.hkey)
		if err != nil {
			if rk.field.required {
				return fmt.Errorf("registry: required key '%s' could not be opened.", rk.path)
			} else {
				rk.skip = true
				return nil
			}
		}

		// Close the registry key when we're done.
		defer func() {
			err = syscall.RegCloseKey(rk.hkey)
			if err != nil {
				panic(err)
			}
		}()
	} else {
		rk.hkey = parent
	}

	for _, entry := range rk.subentries {
		err := entry.populate(rk.hkey)
		if err != nil {
			return err
		}
	}
	return nil
}

func (rv *registryValue) populate(parent syscall.Handle) error {
	nameU16, err := syscall.UTF16PtrFromString(rv.field.name)
	if err != nil {
		return err
	}
	var dataLen uint32
	var keyType uint32
	// get length
	err = syscall.RegQueryValueEx(parent, nameU16, nil, &keyType, nil, &dataLen)
	if err != nil {
		if rv.field.required {
			return fmt.Errorf("registry: required value '%s' could not be opened.", rv.field.name)
		} else {
			rv.skip = true
			return nil
		}
	}
	data := make([]byte, int(dataLen))
	err = syscall.RegQueryValueEx(parent, nameU16, nil, nil, &data[0], &dataLen)
	if err != nil {
		return err
	}
	rv.data = data
	rv.kind = int(keyType)
	return nil
}

func (rk *registryKey) unmarshal(val reflect.Value) error {
	if rk.skip {
		return nil
	}
	// registryKeys always get unmarshalled to structs.
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			val.Set(reflect.New(val.Type().Elem()))
		}
		val = val.Elem()
	}

	for _, ent := range rk.subentries {
		newVal := val.FieldByIndex(ent.fieldInfo().index)
		err := ent.unmarshal(newVal)
		if err != nil {
			return err
		}
	}
	return nil
}

const (
	kindUnknown        = -1
	kindBigNumeric int = 1 + iota
	kindNumeric
	kindString
	kindData
	kindMultiString
)

func (rv *registryValue) unmarshal(val reflect.Value) error {
	if rv.skip {
		return nil
	}

	var newKind int = kindUnknown
	var x interface{}
	switch rv.kind {
	case syscall.REG_DWORD_BIG_ENDIAN:
		var v uint32
		bo := binary.BigEndian
		newKind = kindNumeric
		binary.Read(bytes.NewReader(rv.data), bo, &v)
		x = v
	case syscall.REG_DWORD_LITTLE_ENDIAN:
		var v uint32
		bo := binary.LittleEndian
		newKind = kindNumeric
		binary.Read(bytes.NewReader(rv.data), bo, &v)
		x = v
	case syscall.REG_QWORD_LITTLE_ENDIAN:
		var v uint64
		bo := binary.LittleEndian
		newKind = kindBigNumeric
		binary.Read(bytes.NewReader(rv.data), bo, &v)
		x = v
	case syscall.REG_SZ, syscall.REG_EXPAND_SZ:
		x = string(utf16BytesToUTF8(rv.data[:len(rv.data)-2]))
		newKind = kindString
	case syscall.REG_MULTI_SZ:
		multiSzs := strings.Split(string(utf16BytesToUTF8(rv.data)), "\000")
		x = multiSzs[:len(multiSzs)-2]
		newKind = kindMultiString
	case syscall.REG_BINARY:
		x = rv.data
		newKind = kindData
	default:
		return fmt.Errorf("registry: tried to unmarshal registry key '%s' of type 0x%8.08x, but we don't know what do do with it", rv.field.name, rv.kind)
	}

	valKind := val.Kind()
	if valKind == reflect.Ptr {
		val.Set(reflect.New(val.Type().Elem()))
		valKind = val.Type().Elem().Kind()
		val = val.Elem()
	}

	switch valKind {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32:
		if newKind != kindNumeric {
			return fmt.Errorf("registry: tried to unmarshal non-numeric registry key '%s' into a %v", rv.field.name, valKind)
		}
		val.SetUint(uint64(x.(uint32)))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32:
		if newKind != kindNumeric {
			return fmt.Errorf("registry: tried to unmarshal non-numeric registry key '%s' into a %v", rv.field.name, valKind)
		}
		val.SetInt(int64(x.(uint32)))
	case reflect.Uint64:
		if newKind != kindBigNumeric {
			return fmt.Errorf("registry: tried to unmarshal non-bignum registry key '%s' into a %v", rv.field.name, valKind)
		}
		val.SetUint(x.(uint64))
	case reflect.Int64:
		if newKind != kindBigNumeric {
			return fmt.Errorf("registry: tried to unmarshal non-bignum registry key '%s' into a %v", rv.field.name, valKind)
		}
		val.SetInt(int64(x.(uint64)))
	case reflect.Slice:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			if newKind != kindData {
				return fmt.Errorf("registry: tried to unmarshal non-data value '%s' into a %v", rv.field.name, valKind)
			}
			val.SetBytes(x.([]byte))
		} else if val.Type().Elem().Kind() == reflect.String {
			if newKind != kindMultiString {
				return fmt.Errorf("registry: tried to unmarshal non-multistring value '%s' into a %v", rv.field.name, valKind)
			}
			val.Set(reflect.ValueOf(x))
		} else {
			return fmt.Errorf("registry: tried to unmarshal data or multistring value '%s' into non-slice %v", rv.field.name, rv.field)
		}
	case reflect.String:
		if newKind != kindString {
			return fmt.Errorf("registry: tried to unmarshal non-string value '%s' into a %v", rv.field.name, valKind)
		}
		val.SetString(x.(string))
	default:
		return fmt.Errorf("registry: tried to unmarshal registry key '%s' of type 0x%8.08x into unknown go type %v", rv.field.name, rv.kind, valKind)
	}
	return nil
}

func utf16BytesToUTF8(b []byte) []rune {
	utf := make([]uint16, (len(b)+(2-1))/2)
	for i := 0; i+(2-1) < len(b); i += 2 {
		utf[i/2] = binary.LittleEndian.Uint16(b[i:])
	}
	if len(b)/2 < len(utf) {
		utf[len(utf)-1] = utf8.RuneError
	}
	return utf16.Decode(utf)
}
