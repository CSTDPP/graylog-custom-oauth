package roles

// Mapper translates Microsoft Entra App Role names to Graylog role names
// using a configurable mapping.
type Mapper struct {
	roleMap     map[string]string
	defaultRole string
}

// NewMapper creates a Mapper with the given role mapping and default role.
// The roleMap keys are Entra role names; values are the corresponding Graylog
// role names. The defaultRole is returned when no Entra roles match.
func NewMapper(roleMap map[string]string, defaultRole string) *Mapper {
	// Defensive copy so the caller cannot mutate the map after construction.
	rm := make(map[string]string, len(roleMap))
	for k, v := range roleMap {
		rm[k] = v
	}
	return &Mapper{
		roleMap:     rm,
		defaultRole: defaultRole,
	}
}

// Map translates the given Entra App Role names to Graylog role names.
// Duplicate Graylog roles are removed. If no Entra roles produce a match the
// slice contains only the default role. The returned slice is never empty.
func (m *Mapper) Map(entraRoles []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, entraRole := range entraRoles {
		graylogRole, ok := m.roleMap[entraRole]
		if !ok {
			continue
		}
		if seen[graylogRole] {
			continue
		}
		seen[graylogRole] = true
		result = append(result, graylogRole)
	}

	if len(result) == 0 {
		return []string{m.defaultRole}
	}
	return result
}
