// +build windows

package registry

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
)

type registryEntry struct {
	name string
	data []byte
	kind int // syscall.REG_DWORD, etc.

	field reflect.StructField
}

func Parse(hive, path string, i interface{}) error {
	rval := reflect.ValueOf(i)
	if rval.Kind() == reflect.Ptr {
		if rval.Type().Elem().Kind() != reflect.Struct {
			return errors.New("registry: cannot unmarshal into non-struct")
		} else {
			if rval.IsNil() {
				rval.Set(reflect.New(rval.Type().Elem()))
			}
			rval = rval.Elem()
		}
	}
	if rval.Kind() != reflect.Struct {
		return errors.New("registry: cannot unmarshal into non-struct")
	}

	structType := rval.Type()
	entries := map[string]*registryEntry{}
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		tag := field.Tag.Get("registry")
		if tag == "-" {
			continue
		}

		if tag == "" {
			tag = field.Name
		}

		entries[tag] = &registryEntry{
			name:  tag,
			data:  nil,
			kind:  -1,
			field: field,
		}
	}

	err := readRegistry(hive, path, entries)
	if err != nil {
		panic(err)
	}

	for _, entry := range entries {
		err := entry.unmarshal(rval.FieldByIndex(entry.field.Index))
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func readRegistry(hive, path string, entries map[string]*registryEntry) error {
	var rootHandle syscall.Handle
	switch hive {
	case "HKCU":
		rootHandle = syscall.HKEY_CURRENT_USER
	case "HKLM":
		rootHandle = syscall.HKEY_LOCAL_MACHINE
	default:
		return fmt.Errorf("registry: unknown root key '%s'", hive)
	}

	pathU16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		panic(err)
	}

	var hkey syscall.Handle
	err = syscall.RegOpenKeyEx(rootHandle, pathU16, 0, syscall.KEY_READ, &hkey)
	if err != nil {
		panic(err)
	}

	// Close the registry key when we're done.
	defer func() {
		err = syscall.RegCloseKey(hkey)
		if err != nil {
			panic(err)
		}
	}()

	for _, entry := range entries {
		data, kind, err := regQueryValue(hkey, entry.name)
		if err != nil {
			// continue, for now
			entry.kind = -2
			continue
		}
		entry.data = data
		entry.kind = kind
	}
	return nil
}

func regQueryValue(hkey syscall.Handle, name string) ([]byte, int, error) {
	nameU16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, -1, err
	}
	var dataLen uint32
	var keyType uint32
	// get length
	err = syscall.RegQueryValueEx(hkey, nameU16, nil, &keyType, nil, &dataLen)
	if err != nil {
		return nil, -1, err
	}
	data := make([]byte, int(dataLen))
	err = syscall.RegQueryValueEx(hkey, nameU16, nil, nil, &data[0], &dataLen)
	if err != nil {
		return nil, -1, err
	}
	return data, int(keyType), nil
}

const (
	kindUnknown        = -1
	kindBigNumeric int = 1 + iota
	kindNumeric
	kindString
	kindData
	kindMultiString
)

func (entry *registryEntry) unmarshal(val reflect.Value) error {
	var newKind int = kindUnknown
	var x interface{}
	switch entry.kind {
	case syscall.REG_DWORD_BIG_ENDIAN:
		var v uint32
		bo := binary.BigEndian
		newKind = kindNumeric
		binary.Read(bytes.NewReader(entry.data), bo, &v)
		x = v
	case syscall.REG_DWORD_LITTLE_ENDIAN:
		var v uint32
		bo := binary.LittleEndian
		newKind = kindNumeric
		binary.Read(bytes.NewReader(entry.data), bo, &v)
		x = v
	case syscall.REG_QWORD_LITTLE_ENDIAN:
		var v uint64
		bo := binary.LittleEndian
		newKind = kindBigNumeric
		binary.Read(bytes.NewReader(entry.data), bo, &v)
		x = v
	case syscall.REG_SZ, syscall.REG_EXPAND_SZ:
		x = string(utf16BytesToUTF8(entry.data[:len(entry.data)-2]))
		newKind = kindString
	case syscall.REG_MULTI_SZ:
		multiSzs := strings.Split(string(utf16BytesToUTF8(entry.data)), "\000")
		x = multiSzs[:len(multiSzs)-2]
		newKind = kindMultiString
	case syscall.REG_BINARY:
		x = entry.data
		newKind = kindData
	case -2: // missing key
		return nil
	default:
		return fmt.Errorf("registry: tried to unmarshal registry key `%s` of type 0x%8.08x, but we don't know what do do with it", entry.name, entry.kind)
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
			return fmt.Errorf("registry: tried to unmarshal non-numeric registry key '%s' into a %v", entry.name, valKind)
		}
		val.SetUint(uint64(x.(uint32)))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32:
		if newKind != kindNumeric {
			return fmt.Errorf("registry: tried to unmarshal non-numeric registry key '%s' into a %v", entry.name, valKind)
		}
		val.SetInt(int64(x.(uint32)))
	case reflect.Uint64:
		if newKind != kindBigNumeric {
			return fmt.Errorf("registry: tried to unmarshal non-bignum registry key '%s' into a %v", entry.name, valKind)
		}
		val.SetUint(x.(uint64))
	case reflect.Int64:
		if newKind != kindBigNumeric {
			return fmt.Errorf("registry: tried to unmarshal non-bignum registry key '%s' into a %v", entry.name, valKind)
		}
		val.SetInt(int64(x.(uint64)))
	case reflect.Slice:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			if newKind != kindData {
				return fmt.Errorf("registry: tried to unmarshal non-data value `%s` into a %v", entry.name, valKind)
			}
			val.SetBytes(x.([]byte))
		} else if val.Type().Elem().Kind() == reflect.String {
			if newKind != kindMultiString {
				return fmt.Errorf("registry: tried to unmarshal non-multistring value `%s` into a %v", entry.name, valKind)
			}
			val.Set(reflect.ValueOf(x))
		} else {
			return fmt.Errorf("registry: tried to unmarshal data or multistring value `%s` into non-slice %v", entry.name, entry.field)
		}
	case reflect.String:
		if newKind != kindString {
			return fmt.Errorf("registry: tried to unmarshal non-string value `%s` into a %v", entry.name, valKind)
		}
		val.SetString(x.(string))
	default:
		return fmt.Errorf("registry: tried to unmarshal registry key `%s` of type 0x%8.08x into unknown go type %v", entry.name, entry.kind, valKind)
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