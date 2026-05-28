package authentication

import (
	"github.com/aws/aws-lambda-go/events"
)

// APIGatewayCustomAuthorizerResponse represents the expected format of an API Gateway authorization response.
type APIGatewayCustomAuthorizerResponse struct {
	PrincipalID        string                                  `json:"principalId"`
	PolicyDocument     events.APIGatewayCustomAuthorizerPolicy `json:"policyDocument"`
	Context            AuthorizerResponseContext               `json:"context,omitempty"`
	UsageIdentifierKey string                                  `json:"usageIdentifierKey,omitempty"`
}

type AuthorizerResponseContext struct {
	Sub                            *string        `json:"sub,omitempty"`
	AccessToken                    *string        `json:"access_token,omitempty"`
	ClientID                       *string        `json:"client_id,omitempty"`
	Scope                          *string        `json:"scope,omitempty"`
	X5tsha256                      *string        `json:"x5t#S256,omitempty"`
	IsSuperuser                    *BoolString    `json:"is_super_user,omitempty"`
	AdministerOrganisations        StringSlice    `json:"administer_organisations,omitempty"`
	OrganisationDomainRoleMappings MapStringSlice `json:"organisation_domain_role_mappings,omitempty"`
	UserInfo                       *UserInfo      `json:"user_info,omitempty"`
	ClientSoftwareStatement        *string        `json:"client_software_statement,omitempty"`
	FamilyName                     *string        `json:"family_name,omitempty"`
	GivenName                      *string        `json:"given_name,omitempty"`
	Birthdate                      *string        `json:"birthdate,omitempty"`
	Address                        *string        `json:"address,omitempty"`
}

type StringSlice []string
type MapStringSlice map[string][]any
type BoolString bool

type UserInfo struct {
	FamilyName  *string `json:"family_name,omitempty"`
	GivenName   *string `json:"given_name,omitempty"`
	Birthdate   *string `json:"birthdate,omitempty"`
	Email       *string `json:"email,omitempty"`
	PhoneNumber *string `json:"phone_number,omitempty"`
	Passport    *string `json:"passport,omitempty"`
	NationalID  *string `json:"national_id,omitempty"`
	Sub         *string `json:"sub,omitempty"`
}

func (u UserInfo) Equals(v any) bool {
	var uv UserInfo
	var ok bool
	if uv, ok = v.(UserInfo); !ok {
		return false
	}

	return equalPointers(u.GivenName, uv.GivenName) &&
		equalPointers(u.FamilyName, uv.FamilyName) &&
		equalPointers(u.Email, uv.Email) &&
		equalPointers(u.PhoneNumber, uv.PhoneNumber) &&
		equalPointers(u.Passport, uv.Passport) &&
		equalPointers(u.NationalID, uv.NationalID) &&
		equalPointers(u.Sub, uv.Sub)
}

func equalPointers(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a != nil && b != nil && *a == *b {
		return true
	}
	return false
}
