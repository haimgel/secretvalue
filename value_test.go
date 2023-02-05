package secretvalue_test

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"go.haim.dev/secretvalue"
	"gopkg.in/yaml.v2"
	"testing"
)

func TestMarshallNormalValueYAML(t *testing.T) {
	t.Parallel()

	v := secretvalue.NewStringValue("value")

	b, err := yaml.Marshal(v)
	assert.NoError(t, err)
	assert.Equal(t, []byte("value\n"), b)

	newV, err := roundTripValue(v, yaml.Marshal, yaml.Unmarshal)
	assert.NoError(t, err)
	assert.Equal(t, v, newV)
}

func TestMarshallNormalValueJson(t *testing.T) {
	t.Parallel()

	v := secretvalue.NewStringValue("value")

	b, err := json.Marshal(v)
	assert.NoError(t, err)
	assert.Equal(t, []byte("\"value\""), b)

	newV, err := roundTripValue(v, json.Marshal, json.Unmarshal)
	assert.NoError(t, err)
	assert.Equal(t, v, newV)
}

func TestMarshallSecureValueYAML(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	crypter, err := secretvalue.NewSymmetricCrypter(key)
	assert.NoError(t, err)

	v, err := secretvalue.NewEncryptedStringValue("value", crypter)
	assert.NoError(t, err)

	b, err := yaml.Marshal(v)
	assert.NoError(t, err)
	assert.Regexp(t, "\\Asecure: v1:(.+)\n\\z", string(b))

	newV, err := roundTripValue(v, yaml.Marshal, yaml.Unmarshal)
	assert.NoError(t, err)
	assert.Equal(t, v, newV)
	decrypted, err := newV.Value(crypter)
	assert.NoError(t, err)
	assert.Equal(t, "value", decrypted)
}

func TestMarshallSecureValueJSON(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	crypter, err := secretvalue.NewSymmetricCrypter(key)
	assert.NoError(t, err)

	v, err := secretvalue.NewEncryptedStringValue("value", crypter)
	assert.NoError(t, err)

	b, err := yaml.Marshal(v)
	assert.NoError(t, err)
	assert.Regexp(t, []byte("^secure: v1:(.+)"), b)

	newV, err := roundTripValue(v, json.Marshal, json.Unmarshal)
	assert.NoError(t, err)
	assert.Equal(t, v, newV)
	decrypted, err := newV.Value(crypter)
	assert.NoError(t, err)
	assert.Equal(t, "value", decrypted)
}

func roundTripValue(v secretvalue.StringValue, marshal func(v interface{}) ([]byte, error),
	unmarshal func([]byte, interface{}) error,
) (secretvalue.StringValue, error) {
	b, err := marshal(v)
	if err != nil {
		return secretvalue.StringValue{}, err
	}
	var newV secretvalue.StringValue
	err = unmarshal(b, &newV)
	return newV, err
}


func (d DecryptedTestStruct) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v secretvalue.StringValue
	if err := unmarshal(&v); err != nil {
		return err
	}
	decrypted, err := v.Value(nil)
	if err != nil {
		return err
	}
	d.Foo = decrypted
	return nil
}

func TestYamlStructure(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	crypter, err := secretvalue.NewSymmetricCrypter(key)
	assert.NoError(t, err)

	type TestStruct struct {
		Foo secretvalue.StringValue `yaml:"foo"`
	}
	value, err := secretvalue.NewEncryptedStringValue("value", crypter)
	assert.NoError(t, err)
	v := TestStruct{Foo: value}

	b, err := yaml.Marshal(v)
	assert.NoError(t, err)
	assert.Regexp(t, "\\Afoo:\n  secure: v1:(.+)\n\\z", string(b))

	type DecodedString struct {
		string
	}

	func (d *DecodedString) UnmarshalYAML(unmarshal func(interface{}) error) error {

	}

	type DecryptedTestStruct struct {
		Foo DecodedString `yaml:"foo"`
	}

	decryptedStruct := DecryptedTestStruct{}
	assert.NoError(t, yaml.Unmarshal(b, &decryptedStruct))
	assert.Equal(t, "value", decryptedStruct.Foo)
}
