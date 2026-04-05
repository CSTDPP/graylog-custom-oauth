package roles

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func newTestMapper() *Mapper {
	return NewMapper(map[string]string{
		"graylog-admin":  "Admin",
		"graylog-reader": "Reader",
		"graylog-editor": "Editor",
	}, "Reader")
}

func TestMap_SingleRoleMatch(t *testing.T) {
	m := newTestMapper()
	result := m.Map([]string{"graylog-admin"})
	assert.Equal(t, []string{"Admin"}, result)
}

func TestMap_MultipleRolesMatch(t *testing.T) {
	m := newTestMapper()
	result := m.Map([]string{"graylog-admin", "graylog-reader"})
	assert.ElementsMatch(t, []string{"Admin", "Reader"}, result)
}

func TestMap_NoMatch_ReturnsDefault(t *testing.T) {
	m := newTestMapper()
	result := m.Map([]string{"unknown-role"})
	assert.Equal(t, []string{"Reader"}, result)
}

func TestMap_EmptyInput_ReturnsDefault(t *testing.T) {
	m := newTestMapper()
	result := m.Map([]string{})
	assert.Equal(t, []string{"Reader"}, result)
}

func TestMap_NilInput_ReturnsDefault(t *testing.T) {
	m := newTestMapper()
	result := m.Map(nil)
	assert.Equal(t, []string{"Reader"}, result)
}

func TestMap_Deduplication(t *testing.T) {
	m := newTestMapper()
	result := m.Map([]string{"graylog-admin", "graylog-admin"})
	assert.Equal(t, []string{"Admin"}, result)
}

func TestMap_MixedMatchAndUnknown(t *testing.T) {
	m := newTestMapper()
	result := m.Map([]string{"graylog-admin", "unknown"})
	assert.Equal(t, []string{"Admin"}, result)
}

func TestMap_PartialMatch(t *testing.T) {
	m := newTestMapper()
	result := m.Map([]string{"graylog-admin", "nonexistent", "graylog-editor", "also-missing"})
	assert.ElementsMatch(t, []string{"Admin", "Editor"}, result)
	assert.Len(t, result, 2)
}
