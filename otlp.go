package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// The service only touches log record attributes, so an OTLP/HTTP JSON request is decoded into
// generic maps rather than generated protobuf types: every field it does not know about (resource,
// scope, timestamps, body) passes through unchanged. json.Number keeps integers exact.

type object = map[string]any

func decodeLogs(body []byte) (object, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var req object
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("decoding OTLP JSON: %w", err)
	}
	return req, nil
}

// forEachRecord calls fn with each log record's attribute list and its resource's attributes, and
// stores back whatever list fn returns.
func forEachRecord(req object, fn func(attrs []any, resource []any) []any) int {
	n := 0
	for _, rl := range list(req["resourceLogs"]) {
		rlObj, ok := rl.(object)
		if !ok {
			continue
		}
		var resourceAttrs []any
		if res, ok := rlObj["resource"].(object); ok {
			resourceAttrs = list(res["attributes"])
		}
		for _, sl := range list(rlObj["scopeLogs"]) {
			slObj, ok := sl.(object)
			if !ok {
				continue
			}
			for _, lr := range list(slObj["logRecords"]) {
				lrObj, ok := lr.(object)
				if !ok {
					continue
				}
				lrObj["attributes"] = fn(list(lrObj["attributes"]), resourceAttrs)
				n++
			}
		}
	}
	return n
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

// stringAttr returns a string-valued attribute, or "" if it is absent or not a string.
func stringAttr(attrs []any, key string) string {
	for _, a := range attrs {
		kv, ok := a.(object)
		if !ok || kv["key"] != key {
			continue
		}
		if v, ok := kv["value"].(object); ok {
			s, _ := v["stringValue"].(string)
			return s
		}
	}
	return ""
}

// setString sets a string attribute, replacing an existing one with the same key.
func setString(attrs []any, key, value string) []any {
	val := object{"stringValue": value}
	for _, a := range attrs {
		if kv, ok := a.(object); ok && kv["key"] == key {
			kv["value"] = val
			return attrs
		}
	}
	return append(attrs, object{"key": key, "value": val})
}
