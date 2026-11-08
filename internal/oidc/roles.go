// Package oidc resolves and validates OIDC claim-based role assignments.
package oidc

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/knadh/listmonk/internal/auth"
	"github.com/knadh/listmonk/models"
)

// ResolveRoles applies the first matching mapping, retaining defaults for omitted roles.
func ResolveRoles(claims map[string]json.RawMessage, roles []models.OIDCRoleMapping, userRoleID, listRoleID int) (int, int) {
	for _, m := range roles {
		if !claimMatches(claims[m.Claim], m.Match) {
			continue
		}

		if m.UserRoleID != nil {
			userRoleID = *m.UserRoleID
		}

		if m.ListRoleID != nil {
			listRoleID = *m.ListRoleID
		}

		break
	}

	return userRoleID, listRoleID
}

// claimMatches accepts only strings and arrays containing exclusively strings.
func claimMatches(raw json.RawMessage, expected string) bool {
	var claim any
	if err := json.Unmarshal(raw, &claim); err != nil {
		return false
	}

	switch v := claim.(type) {
	case string:
		return v == expected
	case []any:
		matched := false
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return false
			}
			matched = matched || s == expected
		}

		return matched
	}

	return false
}

// validateRoles checks mapping fields and references to each role type.
func validateRoles(roles []models.OIDCRoleMapping, userRoles []auth.Role, listRoles []auth.ListRole) error {
	for i, m := range roles {
		var msg string
		switch {
		case m.Claim == "":
			msg = "claim is required"
		case m.Match == "":
			msg = "match is required"
		case m.UserRoleID != nil && !slices.ContainsFunc(userRoles, func(r auth.Role) bool { return r.ID == *m.UserRoleID }):
			msg = fmt.Sprintf("user role ID %d does not exist", *m.UserRoleID)
		case m.ListRoleID != nil && !slices.ContainsFunc(listRoles, func(r auth.ListRole) bool { return r.ID == *m.ListRoleID }):
			msg = fmt.Sprintf("list role ID %d does not exist", *m.ListRoleID)
		}

		if msg != "" {
			return fmt.Errorf("OIDC role mapping %d: %s", i+1, msg)
		}
	}

	return nil
}

// ValidateSettings checks defaults even when automatic user creation is disabled.
func ValidateSettings(set models.Settings, userRoles []auth.Role, listRoles []auth.ListRole) error {
	o := set.OIDC
	if o.AutoCreateUsers || o.SyncRolesOnLogin || o.DefaultUserRoleID.Valid {
		if !o.DefaultUserRoleID.Valid || !slices.ContainsFunc(userRoles, func(r auth.Role) bool { return r.ID == o.DefaultUserRoleID.Int }) {
			return fmt.Errorf("OIDC default user role ID %d does not exist", o.DefaultUserRoleID.Int)
		}
	}
	if o.DefaultListRoleID.Valid && !slices.ContainsFunc(listRoles, func(r auth.ListRole) bool { return r.ID == o.DefaultListRoleID.Int }) {
		return fmt.Errorf("OIDC default list role ID %d does not exist", o.DefaultListRoleID.Int)
	}
	return validateRoles(o.Roles, userRoles, listRoles)
}
