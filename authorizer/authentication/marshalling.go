package authentication

import (
	"encoding/json"
	"regexp"
	"strings"
)

var phoneRe = regexp.MustCompile(`\+?[0-9]{2}([0-9]+)[0-9]{3}`)
var idRe = regexp.MustCompile(`([0-9]+)[0-9]{2}`)

func BoolStringPtr(b BoolString) *BoolString {
	return &b
}

func (s StringSlice) MarshalJSON() ([]byte, error) {
	if len(s) == 0 {
		return []byte(`"[]"`), nil
	}
	b, err := json.Marshal([]string(s))
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(b))
}

func (s *StringSlice) UnmarshalJSON(data []byte) error {
	if string(data) == "[]" {
		return nil
	}
	var jsonString string
	if err := json.Unmarshal(data, &jsonString); err != nil {
		return err
	}
	jsonString = strings.Trim(jsonString, `"`)

	var strSlice []string
	if err := json.Unmarshal([]byte(jsonString), &strSlice); err != nil {
		return err
	}

	*s = strSlice
	return nil
}

func (m MapStringSlice) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	b, err := json.Marshal(map[string][]any(m))
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(b))
}

func (m *MapStringSlice) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var jsonString string
	if err := json.Unmarshal(data, &jsonString); err != nil {
		return err
	}
	jsonString = strings.Trim(jsonString, `"`)

	var mapStrSlice map[string][]any
	if err := json.Unmarshal([]byte(jsonString), &mapStrSlice); err != nil {
		return err
	}

	*m = mapStrSlice
	return nil
}

func (b *BoolString) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	bytes, err := json.Marshal(*b)
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(bytes))
}

func (b *BoolString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var jsonString string
	if err := json.Unmarshal(data, &jsonString); err != nil {
		return err
	}
	jsonString = strings.Trim(jsonString, `"`)

	var bl bool
	if err := json.Unmarshal([]byte(jsonString), &bl); err != nil {
		return err
	}
	*b = BoolString(bl)
	return nil
}

func (u *UserInfo) MarshalJSON() ([]byte, error) {
	if u == nil {
		return []byte("null"), nil
	}
	bytes, err := json.Marshal(*u)
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(bytes))
}

func (u *UserInfo) UnmarshalJSON(data []byte) error {
	type InternalInfo struct {
		GivenName   *string `json:"given_name,omitempty"`
		FamilyName  *string `json:"family_name,omitempty"`
		Birthdate   *string `json:"birthdate,omitempty"`
		Email       *string `json:"email,omitempty"`
		PhoneNumber *string `json:"phone_number,omitempty"`
		Passport    *string `json:"passport,omitempty"`
		NationalID  *string `json:"national_id,omitempty"`
		Sub         *string `json:"sub,omitempty"`
	}

	if string(data) == "null" {
		return nil
	}

	var ui InternalInfo
	if err := json.Unmarshal(data, &ui); err != nil {
		if strings.ContainsAny(err.Error(), "json: cannot unmarshal string into Go struct field") {
			var jsonString string
			if err = json.Unmarshal(data, &jsonString); err != nil {
				return err
			}
			jsonString = strings.Trim(jsonString, `"`)
			if err = json.Unmarshal([]byte(jsonString), &ui); err != nil {
				return err
			}
		}
		return err
	}

	u.Sub = ui.Sub
	u.GivenName = ui.GivenName
	u.FamilyName = ui.FamilyName
	u.Birthdate = ui.Birthdate
	u.Email = ui.Email
	u.PhoneNumber = ui.PhoneNumber
	u.Passport = ui.Passport
	u.NationalID = ui.NationalID

	return nil
}
