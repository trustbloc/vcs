/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package attributeutil_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"github.com/trustbloc/vcs/pkg/observability/tracing/attributeutil"
)

func TestJSON(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		opts []attributeutil.Opt
		want attribute.KeyValue
	}{
		{
			name: "no redaction",
			val:  map[string]interface{}{"foo": "bar"},
			opts: nil,
			want: attribute.KeyValue{Key: attribute.Key("key"), Value: attribute.StringValue(`{"foo":"bar"}`)},
		},
		{
			name: "foo redacted",
			val:  map[string]interface{}{"foo": "bar"},
			opts: []attributeutil.Opt{attributeutil.WithRedacted("foo")},
			want: attribute.KeyValue{Key: attribute.Key("key"), Value: attribute.StringValue(`{"foo":"[REDACTED]"}`)},
		},
		{
			name: "nested bar redacted",
			val:  map[string]interface{}{"foo": map[string]interface{}{"bar": "baz"}},
			opts: []attributeutil.Opt{attributeutil.WithRedacted("foo.bar")},
			want: attribute.KeyValue{Key: attribute.Key("key"), Value: attribute.StringValue(`{"foo":{"bar":"[REDACTED]"}}`)}, //nolint:lll
		},
		{
			name: "foo redacted in array",
			val:  []map[string]interface{}{{"foo": "bar"}, {"foo": "baz"}},
			opts: []attributeutil.Opt{attributeutil.WithRedacted("#.foo")},
			want: attribute.KeyValue{Key: attribute.Key("key"), Value: attribute.StringValue(`[{"foo":"[REDACTED]"},{"foo":"[REDACTED]"}]`)}, //nolint:lll
		},
		{
			name: "path not found",
			val:  map[string]interface{}{"foo": map[string]interface{}{"bar": "baz"}},
			opts: []attributeutil.Opt{attributeutil.WithRedacted("foo.missing")},
			want: attribute.KeyValue{Key: attribute.Key("key"), Value: attribute.StringValue(`{"foo":{"bar":"baz"}}`)},
		},
		{
			name: "nil value",
			val:  nil,
			opts: nil,
			want: attribute.KeyValue{Key: attribute.Key("key"), Value: attribute.StringValue(`null`)},
		},
		{
			name: "empty value",
			val:  "",
			opts: nil,
			want: attribute.KeyValue{Key: attribute.Key("key"), Value: attribute.StringValue(`""`)},
		},
		{
			name: "fail to marshal",
			val:  func() {},
			opts: nil,
			want: attribute.KeyValue{Key: attribute.Key("key"), Value: attribute.Value{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := attributeutil.JSON("key", tt.val, tt.opts...)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFormValues(t *testing.T) {
	tests := []struct {
		name   string
		params map[string][]string
		opts   []attributeutil.Opt
		check  func(t *testing.T, got attribute.KeyValue)
	}{
		{
			name:   "no redaction",
			params: map[string][]string{"foo": {"bar"}, "baz": {"qux"}},
			opts:   nil,
			check: func(t *testing.T, got attribute.KeyValue) {
				t.Helper()

				require.Equal(t, attribute.Key("key"), got.Key)
				require.True(t, got.Value.AsString() == `foo=bar&baz=qux` ||
					got.Value.AsString() == `baz=qux&foo=bar`,
				)
			},
		},
		{
			name:   "foo redacted",
			params: map[string][]string{"foo": {"bar"}, "baz": {"qux"}},
			opts:   []attributeutil.Opt{attributeutil.WithRedacted("foo")},
			check: func(t *testing.T, got attribute.KeyValue) {
				t.Helper()

				require.Equal(t, attribute.Key("key"), got.Key)
				require.True(t, got.Value.AsString() == `foo=[REDACTED]&baz=qux` ||
					got.Value.AsString() == `baz=qux&foo=[REDACTED]`,
				)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := attributeutil.FormParams("key", tt.params, tt.opts...)
			tt.check(t, got)
		})
	}
}
