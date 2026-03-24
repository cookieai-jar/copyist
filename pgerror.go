// Copyright 2020 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package copyist

// This file inlines the subset of pgproto3.ErrorResponse and pgconn.PgError
// that copyist needs for encoding/decoding Postgres error messages in recording
// files. This avoids transitive dependencies on github.com/jackc/pgproto3/v2
// (CVE-2026-4427) and github.com/jackc/pgconn.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strconv"
)

// pgErrorResponse holds Postgres error fields and provides wire-protocol
// encode/decode. Mirrors pgproto3.ErrorResponse and pgconn.PgError.
type pgErrorResponse struct {
	Severity         string
	Code             string
	Message          string
	Detail           string
	Hint             string
	Position         int32
	InternalPosition int32
	InternalQuery    string
	Where            string
	SchemaName       string
	TableName        string
	ColumnName       string
	DataTypeName     string
	ConstraintName   string
	File             string
	Line             int32
	Routine          string
}

// Error implements the error interface, matching pgconn.PgError's format.
func (e *pgErrorResponse) Error() string {
	return e.Severity + ": " + e.Message + " (SQLSTATE " + e.Code + ")"
}

// decode decodes src into the receiver. src must contain the message body
// (without the 1-byte type identifier and 4-byte length prefix).
func (dst *pgErrorResponse) decode(src []byte) error {
	*dst = pgErrorResponse{}
	buf := bytes.NewBuffer(src)

	for {
		k, err := buf.ReadByte()
		if err != nil {
			return err
		}
		if k == 0 {
			break
		}

		vb, err := buf.ReadBytes(0)
		if err != nil {
			return err
		}
		v := string(vb[:len(vb)-1])

		switch k {
		case 'S':
			dst.Severity = v
		case 'C':
			dst.Code = v
		case 'M':
			dst.Message = v
		case 'D':
			dst.Detail = v
		case 'H':
			dst.Hint = v
		case 'P':
			n, _ := strconv.ParseInt(v, 10, 32)
			dst.Position = int32(n)
		case 'p':
			n, _ := strconv.ParseInt(v, 10, 32)
			dst.InternalPosition = int32(n)
		case 'q':
			dst.InternalQuery = v
		case 'W':
			dst.Where = v
		case 's':
			dst.SchemaName = v
		case 't':
			dst.TableName = v
		case 'c':
			dst.ColumnName = v
		case 'd':
			dst.DataTypeName = v
		case 'n':
			dst.ConstraintName = v
		case 'F':
			dst.File = v
		case 'L':
			n, _ := strconv.ParseInt(v, 10, 32)
			dst.Line = int32(n)
		case 'R':
			dst.Routine = v
		}
	}

	return nil
}

// encode encodes the error response into the Postgres wire protocol format.
// The returned bytes include the 1-byte message type ('E') and 4-byte length.
func (src *pgErrorResponse) encode(dst []byte) ([]byte, error) {
	dst = append(dst, 'E')
	sp := len(dst)
	dst = appendInt32(dst, -1)

	dst = appendField(dst, 'S', src.Severity)
	dst = appendField(dst, 'C', src.Code)
	dst = appendField(dst, 'M', src.Message)
	dst = appendField(dst, 'D', src.Detail)
	dst = appendField(dst, 'H', src.Hint)
	if src.Position != 0 {
		dst = appendField(dst, 'P', strconv.Itoa(int(src.Position)))
	}
	if src.InternalPosition != 0 {
		dst = appendField(dst, 'p', strconv.Itoa(int(src.InternalPosition)))
	}
	dst = appendField(dst, 'q', src.InternalQuery)
	dst = appendField(dst, 'W', src.Where)
	dst = appendField(dst, 's', src.SchemaName)
	dst = appendField(dst, 't', src.TableName)
	dst = appendField(dst, 'c', src.ColumnName)
	dst = appendField(dst, 'd', src.DataTypeName)
	dst = appendField(dst, 'n', src.ConstraintName)
	dst = appendField(dst, 'F', src.File)
	if src.Line != 0 {
		dst = appendField(dst, 'L', strconv.Itoa(int(src.Line)))
	}
	dst = appendField(dst, 'R', src.Routine)

	dst = append(dst, 0)

	messageBodyLen := len(dst[sp:])
	if messageBodyLen > 1073741820 {
		return nil, errors.New("message body too large")
	}
	binary.BigEndian.PutUint32(dst[sp:], uint32(int32(messageBodyLen)))

	return dst, nil
}

func appendField(dst []byte, k byte, v string) []byte {
	if v == "" {
		return dst
	}
	dst = append(dst, k)
	dst = append(dst, v...)
	dst = append(dst, 0)
	return dst
}

func appendInt32(buf []byte, n int32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(n))
	return append(buf, b...)
}

// tryExtractPgConnError uses reflection to detect a *pgconn.PgError (or any
// struct with the same field layout) without importing pgconn. Returns a
// pgErrorResponse and true if the value matches, or zero value and false.
func tryExtractPgConnError(val interface{}) (pgErrorResponse, bool) {
	v := reflect.ValueOf(val)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return pgErrorResponse{}, false
	}

	severity := v.FieldByName("Severity")
	code := v.FieldByName("Code")
	message := v.FieldByName("Message")
	if !severity.IsValid() || !code.IsValid() || !message.IsValid() {
		return pgErrorResponse{}, false
	}

	// Verify it's a PgError-shaped struct by checking the type name
	typeName := v.Type().Name()
	if typeName != "PgError" {
		return pgErrorResponse{}, false
	}

	return pgErrorResponse{
		Severity:         stringField(v, "Severity"),
		Code:             stringField(v, "Code"),
		Message:          stringField(v, "Message"),
		Detail:           stringField(v, "Detail"),
		Hint:             stringField(v, "Hint"),
		Position:         int32Field(v, "Position"),
		InternalPosition: int32Field(v, "InternalPosition"),
		InternalQuery:    stringField(v, "InternalQuery"),
		Where:            stringField(v, "Where"),
		SchemaName:       stringField(v, "SchemaName"),
		TableName:        stringField(v, "TableName"),
		ColumnName:       stringField(v, "ColumnName"),
		DataTypeName:     stringField(v, "DataTypeName"),
		ConstraintName:   stringField(v, "ConstraintName"),
		File:             stringField(v, "File"),
		Line:             int32Field(v, "Line"),
		Routine:          stringField(v, "Routine"),
	}, true
}

func stringField(v reflect.Value, name string) string {
	f := v.FieldByName(name)
	if !f.IsValid() || f.Kind() != reflect.String {
		return ""
	}
	return f.String()
}

func int32Field(v reflect.Value, name string) int32 {
	f := v.FieldByName(name)
	if !f.IsValid() || f.Kind() != reflect.Int32 {
		return 0
	}
	return int32(f.Int())
}
