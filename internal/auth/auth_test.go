package auth

import (
	"net/http"
	"reflect"
	"testing"
)

func TestGetKey(t *testing.T) {

	h := make(http.Header)

	k := "YWxhZGRpbjpvcGVuc2VzYW1l"

	h.Add("Authorization", "ApiKey "+k)

	got, _ := GetAPIKey(h)
	want := k
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("expected: %v, got: %v", want, got)
	}
}

func TestGetKeyNoHeader(t *testing.T) {

	h := make(http.Header)

	_, err := GetAPIKey(h)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected: %v, got: %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetKeyInvalidHeader(t *testing.T) {

	h := make(http.Header)

	k := "YWxhZGRpbjpvcGVuc2VzYW1l"
	h.Add("Authorization", "Bearer "+k)

	_, err := GetAPIKey(h)
	expectedErr := "malformed authorization header"
	actualErr := err.Error()

	if expectedErr == actualErr {
		t.Fatalf("expected: %v, got: %v", expectedErr, actualErr)
	}
}
