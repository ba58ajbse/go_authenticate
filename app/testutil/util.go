package testutil

import (
	"bytes"
	"encoding/json"
	"strings"
)

func FormatBodyForTest(v interface{}, recBody *bytes.Buffer) (string, string) {
	expected := FormatModelDataToJsonStr(v)
	actual := RemoveLFForRecBody(recBody)

	return expected, actual
}

func FormatModelDataToJsonStr(v interface{}) string {
	out, _ := json.Marshal(v)
	jsonStr := string(out)

	return jsonStr
}

func RemoveLFForRecBody(recBody *bytes.Buffer) string {
	str := strings.TrimRight(recBody.String(), "\n")

	return str
}
