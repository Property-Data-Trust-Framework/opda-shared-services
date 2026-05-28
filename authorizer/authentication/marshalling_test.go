//go:build !conformance

package authentication

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAuthorizerResponseContext_Marshalling(t *testing.T) {
	tests := []struct {
		name, data string
		arc        AuthorizerResponseContext
	}{
		{
			name: "empty",
			data: `{}`,
			arc:  AuthorizerResponseContext{},
		},
		{
			name: "AccessToken",
			data: `{"access_token":"foo"}`,
			arc: AuthorizerResponseContext{
				AccessToken: Pointer("foo"),
			},
		},
		{
			name: "administer_organisations",
			data: `{"administer_organisations":"[\"bar\",\"foo\"]"}`,
			arc: AuthorizerResponseContext{
				AdministerOrganisations: []string{"bar", "foo"},
			},
		},
		{
			name: "organisation_domain_role_mappings",
			data: `{"organisation_domain_role_mappings":"{\"bar\":[\"foo\"]}"}`,
			arc: AuthorizerResponseContext{
				OrganisationDomainRoleMappings: MapStringSlice{
					"bar": {"foo"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.arc)
			if err != nil {
				t.Fatalf("no error should be thrown: %s", err.Error())
			}
			if tt.data != string(data) {
				t.Fatalf("expected: %s but got %s", tt.data, string(data))
			}

			var arc AuthorizerResponseContext
			if json.Unmarshal(data, &arc) != nil {
				t.Fatalf("no error should be thrown: %s", err.Error())
			}
			if !reflect.DeepEqual(tt.arc, arc) {
				t.Fatalf("expected %v but got %v", tt.arc, arc)
			}
		})
	}
}
