//go:build !conformance

package authentication

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"maps"
	"reflect"
	"testing"
)

func TestAuthorizerResponseContextIsValidJSON(t *testing.T) {
	// see https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
	auth := AuthorizerResponseContext{
		Sub:                            Pointer("sub"),
		AccessToken:                    Pointer("access_token"),
		ClientID:                       Pointer("client_id"),
		Scope:                          Pointer("scope"),
		X5tsha256:                      Pointer("x5tsha256"),
		IsSuperuser:                    BoolStringPtr(true),
		AdministerOrganisations:        StringSlice{"foo", "bar"},
		OrganisationDomainRoleMappings: MapStringSlice{"foo": {"bar", "baz"}},
		UserInfo: &UserInfo{
			GivenName:   Pointer("given_name"),
			FamilyName:  Pointer("family_name"),
			Email:       Pointer("email"),
			PhoneNumber: Pointer("phone_number"),
			Passport:    Pointer("passport"),
			NationalID:  Pointer("national_id"),
			Sub:         Pointer("sub"),
		},
		ClientSoftwareStatement: Pointer("client_software_statement"),
	}

	b, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("no error should be thrown: %s", err.Error())
	}

	data := map[string]any{}
	if json.Unmarshal(b, &data) != nil {
		t.Fatalf("no error should be thrown: %s", err.Error())
	}
	for k, v := range data {
		switch v.(type) {
		case string:
		default:
			t.Errorf("unexpected type %T only stringified values are allow for key: %s", v, k)
		}
	}
}

func TestUserInfo_MaskUserAttributes(t *testing.T) {
	tests := []struct {
		name           string
		ui             UserInfo
		expectedOutput string
	}{
		{
			name:           "Empty does no masking",
			ui:             UserInfo{},
			expectedOutput: "{\"level\":\"INFO\",\"message\":\"User object\",\"ui\":null}\n",
		},

		{
			name: "Masks all fields",
			ui: UserInfo{
				GivenName:   Pointer("foo"),
				FamilyName:  Pointer("foo"),
				Email:       Pointer("foo@email.com"),
				PhoneNumber: Pointer("01234567890"),
				Passport:    Pointer("123456789"),
				NationalID:  Pointer("123456789"),
			},
			expectedOutput: "{\"level\":\"INFO\",\"message\":\"User object\",\"ui\":{\"first_name\":\"foo\",\"last_name\":\"foo\",\"email\":\"foo@email.com\",\"phone_number\":\"01******890\",\"passport\":\"*******89\",\"national_id\":\"*******89\"}}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey && len(groups) == 0 {
					return slog.Attr{}
				}
				if a.Key == slog.MessageKey {
					a.Key = "message"
				}
				return a
			}}))
			logger.Info("User object", slog.Any("ui", tt.ui))
			t.Logf("heres some output %s", buf.String())
			if tt.expectedOutput != buf.String() {
				t.Fatalf("output does not match expected result - got: %s, expected: %s", buf.String(), tt.expectedOutput)
			}
		})
	}
}

func TestAuthorizerResponseContext_PepInput(t *testing.T) {
	tests := []struct {
		name string
		arc  AuthorizerResponseContext
		pep  map[string]any
	}{
		{
			name: "Empty",
			arc:  AuthorizerResponseContext{},
			pep:  map[string]any{},
		},
		{
			name: "All present",
			arc: AuthorizerResponseContext{
				Sub:                     Pointer("foo"),
				AccessToken:             Pointer("foo"),
				ClientID:                Pointer("foo"),
				Scope:                   Pointer("foo bar"),
				X5tsha256:               Pointer("foo"),
				IsSuperuser:             BoolStringPtr(true),
				AdministerOrganisations: []string{"bar", "foo"},
				OrganisationDomainRoleMappings: MapStringSlice{
					"bar": {"foo"},
				},
				UserInfo: &UserInfo{
					GivenName:   Pointer("foo"),
					FamilyName:  Pointer("foo"),
					Email:       Pointer("foo"),
					PhoneNumber: Pointer("foo"),
					Passport:    Pointer("foo"),
					NationalID:  Pointer("foo"),
					Sub:         Pointer("foo"),
				},
				ClientSoftwareStatement: Pointer("foo"),
			},
			pep: map[string]any{
				"sub":                      "foo",
				"access_token":             "foo",
				"client_id":                "foo",
				"scope":                    []string{"foo", "bar"},
				"x5t#S256":                 "foo",
				"is_super_user":            BoolString(true),
				"administer_organisations": []string{"bar", "foo"},
				"organisation_domain_role_mappings": MapStringSlice{
					"bar": {"foo"},
				},
				"user_info": UserInfo{
					GivenName:   Pointer("foo"),
					FamilyName:  Pointer("foo"),
					Email:       Pointer("foo"),
					PhoneNumber: Pointer("foo"),
					Passport:    Pointer("foo"),
					NationalID:  Pointer("foo"),
					Sub:         Pointer("foo"),
				},
				"client_software_statement": "foo",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pep := tt.arc.PepInput()
			if !maps.EqualFunc(tt.pep, pep, reflect.DeepEqual) {
				t.Fatalf("returned pep does not match expected values - got: %v, expected: %v", pep, tt.pep)
			}
		})
	}
}
