package secretvalue

import (
	"encoding/json"
	"errors"
	"fmt"
)

type StringValue struct {
	value  string
	secure bool
}

type SecureValue struct {
	Secure string `json:"secure" yaml:"secure"`
}

func NewStringValue(value string) StringValue {
	return StringValue{value: value, secure: false}
}

func NewEncryptedStringValue(value string, encrypter Encrypter) (StringValue, error) {
	if encrypter == nil {
		return StringValue{}, errors.New("non-nil encrypter required")
	}
	encryptedValue, err := encrypter.EncryptValue(value)
	if err != nil {
		return StringValue{}, err
	}
	return StringValue{value: encryptedValue, secure: true}, nil
}

func (c *StringValue) Value(decrypter Decrypter) (string, error) {
	if !c.secure {
		return c.value, nil
	}
	if decrypter == nil {
		return "", errors.New("non-nil decrypter required")
	}
	return decrypter.DecryptValue(c.value)
}

func (c *StringValue) marshalValue() (interface{}, error) {
	if !c.secure {
		return c.value, nil
	}
	m := make(map[string]string)
	m["secure"] = c.value
	return m, nil
}

func (c *StringValue) unmarshalValue(unmarshal func(interface{}) error) error {
	// First, try to unmarshal as a string.
	err := unmarshal(&c.value)
	if err == nil {
		c.secure = false
		return nil
	}

	// Otherwise, try to unmarshal as a secure object.
	var obj SecureValue
	if err = unmarshal(&obj); err != nil {
		return fmt.Errorf("malformed value: %w", err)
	}
	c.value = obj.Secure
	c.secure = true
	return nil
}

func (c StringValue) MarshalJSON() ([]byte, error) {
	v, err := c.marshalValue()
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (c *StringValue) UnmarshalJSON(b []byte) error {
	return c.unmarshalValue(
		func(v interface{}) error {
			return json.Unmarshal(b, v)
		})
}

func (c StringValue) MarshalYAML() (interface{}, error) {
	return c.marshalValue()
}

func (c *StringValue) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return c.unmarshalValue(func(v interface{}) error {
		return unmarshal(v)
	})
}
