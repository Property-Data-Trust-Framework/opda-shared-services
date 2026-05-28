package authentication

import (
	"log/slog"
	"regexp"
	"strings"
)

// PepInput because OPA requires an input comprised of basic types
// we need to convert the AuthorizerResponseContext to a map[string]any
// containing only basic types
func (a AuthorizerResponseContext) PepInput() map[string]any {
	m := map[string]any{}
	if a.Sub != nil {
		m["sub"] = *a.Sub
	}
	if a.AccessToken != nil {
		m["access_token"] = *a.AccessToken
	}
	if a.ClientID != nil {
		m["client_id"] = *a.ClientID
	}
	if a.Scope != nil {
		m["scope"] = strings.Split(*a.Scope, " ")
	}
	if a.X5tsha256 != nil {
		m["x5t#S256"] = *a.X5tsha256
	}
	if a.IsSuperuser != nil {
		m["is_super_user"] = *a.IsSuperuser
	}
	if a.AdministerOrganisations != nil {
		m["administer_organisations"] = []string(a.AdministerOrganisations)
	}
	if a.OrganisationDomainRoleMappings != nil {
		m["organisation_domain_role_mappings"] = a.OrganisationDomainRoleMappings
	}
	if a.UserInfo != nil {
		m["user_info"] = *a.UserInfo
	}
	if a.ClientSoftwareStatement != nil {
		m["client_software_statement"] = *a.ClientSoftwareStatement
	}
	return m
}

func (u UserInfo) LogValue() slog.Value {
	var attrs []slog.Attr
	if u.GivenName != nil {
		attrs = append(attrs, slog.String("first_name", *u.GivenName))
	}
	if u.FamilyName != nil {
		attrs = append(attrs, slog.String("last_name", *u.FamilyName))
	}
	if u.Email != nil {
		attrs = append(attrs, slog.String("email", *u.Email))
	}
	if u.PhoneNumber != nil {
		attrs = append(attrs, slog.String("phone_number", mask(phoneRe, *u.PhoneNumber)))
	}
	if u.Passport != nil {
		attrs = append(attrs, slog.String("passport", mask(idRe, *u.Passport)))
	}
	if u.NationalID != nil {
		attrs = append(attrs, slog.String("national_id", mask(idRe, *u.NationalID)))
	}
	if u.Sub != nil {
		attrs = append(attrs, slog.String("sub", *u.Sub))
	}
	if len(attrs) == 0 {
		return slog.AnyValue(nil)
	}
	return slog.GroupValue(attrs...)
}

func mask(re *regexp.Regexp, s string) string {
	maskedSubstring := re.ReplaceAllString(s, `$1`)
	return strings.ReplaceAll(s, maskedSubstring, strings.Repeat("*", len(maskedSubstring)))
}
