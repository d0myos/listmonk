package oidc

import (
	"encoding/json"
	"testing"

	"github.com/knadh/listmonk/internal/auth"
	"github.com/knadh/listmonk/models"
	"gopkg.in/volatiletech/null.v6"
)

func TestResolveRolesFromClaims(t *testing.T) {
	adminRole, editorRole, listRole := 1, 2, 10
	mappings := []models.OIDCRoleMapping{
		{Claim: "groups", Match: "admins", UserRoleID: &adminRole, ListRoleID: &listRole},
		{Claim: "groups", Match: "editors", UserRoleID: &editorRole},
	}

	// The resolver is stateless: each result is calculated from configured defaults.
	for _, tc := range []struct {
		name, claim string
		user, list  int
	}{
		{"admin mapping", `["admins"]`, 1, 10},
		{"editor mapping uses default list role", `["editors"]`, 2, 0},
		{"unmapped group returns defaults", `["guests"]`, 3, 0},
		{"missing claim returns defaults", ``, 3, 0},
		{"empty group returns defaults", `[]`, 3, 0},
		{"mixed array after matching string is rejected", `["admins",42]`, 3, 0},
		{"mixed array before matching string is rejected", `[42,"admins"]`, 3, 0},
		{"case sensitive", `"Admins"`, 3, 0},
		{"no substring match", `"superadmins"`, 3, 0},
		{"invalid JSON", `{"groups":`, 3, 0},
		{"null claim", `null`, 3, 0},
		{"boolean claim", `true`, 3, 0},
		{"numeric claim", `42`, 3, 0},
		{"object claim", `{"name":"admins"}`, 3, 0},
		{"string claim", `"editors"`, 2, 0},
		{"first mapping wins", `["editors","admins"]`, 1, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]json.RawMessage{}
			if tc.claim != "" {
				claims["groups"] = json.RawMessage(tc.claim)
			}
			user, list := ResolveRoles(claims, mappings, 3, 0)
			if user != tc.user || list != tc.list {
				t.Fatalf("got roles (%d, %d), want (%d, %d)", user, list, tc.user, tc.list)
			}
		})
	}
}

func TestValidateOIDCSyncRolesSettings(t *testing.T) {
	userRoles := []auth.Role{{ID: 1}, {ID: 2}}
	listRoles := []auth.ListRole{{ID: 10}}
	for _, tc := range []struct {
		name        string
		sync        bool
		defaultUser null.Int
		defaultList null.Int
		wantErr     bool
	}{
		{"disabled accepts absent defaults", false, null.Int{}, null.Int{}, false},
		{"sync requires default without auto creation", true, null.Int{}, null.Int{}, true},
		{"unknown default user role", true, null.NewInt(99, true), null.Int{}, true},
		{"valid default without list role", true, null.NewInt(2, true), null.Int{}, false},
		{"valid defaults", true, null.NewInt(2, true), null.NewInt(10, true), false},
		{"unknown default list role", true, null.NewInt(2, true), null.NewInt(99, true), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var set models.Settings
			set.OIDC.SyncRolesOnLogin = tc.sync
			set.OIDC.DefaultUserRoleID = tc.defaultUser
			set.OIDC.DefaultListRoleID = tc.defaultList
			if err := ValidateSettings(set, userRoles, listRoles); (err != nil) != tc.wantErr {
				t.Fatalf("ValidateSettings() error = %v, want error: %v", err, tc.wantErr)
			}
		})
	}
}

func TestResolveRolesUsesNonzeroDefaults(t *testing.T) {
	editor, list := 2, 10
	for _, tc := range []struct {
		name               string
		mappings           []models.OIDCRoleMapping
		wantUser, wantList int
	}{
		{"no mappings", nil, 3, 11},
		{"unmatched mapping", []models.OIDCRoleMapping{{Claim: "groups", Match: "admins", UserRoleID: &editor, ListRoleID: &list}}, 3, 11},
		{"user-only mapping retains list default", []models.OIDCRoleMapping{{Claim: "groups", Match: "editors", UserRoleID: &editor}}, 2, 11},
		{"list-only mapping retains user default", []models.OIDCRoleMapping{{Claim: "groups", Match: "editors", ListRoleID: &list}}, 3, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, list := ResolveRoles(map[string]json.RawMessage{"groups": json.RawMessage(`"editors"`)}, tc.mappings, 3, 11)
			if user != tc.wantUser || list != tc.wantList {
				t.Fatalf("got (%d, %d), want (%d, %d)", user, list, tc.wantUser, tc.wantList)
			}
		})
	}
}

func TestValidateSettingsMappings(t *testing.T) {
	userID, listID, unknown := 2, 10, 99
	for _, tc := range []struct {
		name    string
		mapping models.OIDCRoleMapping
		want    string
	}{
		{"valid both roles", models.OIDCRoleMapping{Claim: "groups", Match: "editors", UserRoleID: &userID, ListRoleID: &listID}, ""},
		{"valid user only", models.OIDCRoleMapping{Claim: "groups", Match: "editors", UserRoleID: &userID}, ""},
		{"valid list only", models.OIDCRoleMapping{Claim: "groups", Match: "editors", ListRoleID: &listID}, ""},
		{"missing claim", models.OIDCRoleMapping{Match: "editors", UserRoleID: &userID}, "OIDC role mapping 1: claim is required"},
		{"missing match", models.OIDCRoleMapping{Claim: "groups", UserRoleID: &userID}, "OIDC role mapping 1: match is required"},
		{"unknown user role", models.OIDCRoleMapping{Claim: "groups", Match: "editors", UserRoleID: &unknown}, "OIDC role mapping 1: user role ID 99 does not exist"},
		{"unknown list role", models.OIDCRoleMapping{Claim: "groups", Match: "editors", ListRoleID: &unknown}, "OIDC role mapping 1: list role ID 99 does not exist"},
		{"list role used as user role", models.OIDCRoleMapping{Claim: "groups", Match: "editors", UserRoleID: &listID}, "OIDC role mapping 1: user role ID 10 does not exist"},
		{"user role used as list role", models.OIDCRoleMapping{Claim: "groups", Match: "editors", ListRoleID: &userID}, "OIDC role mapping 1: list role ID 2 does not exist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var set models.Settings
			set.OIDC.SyncRolesOnLogin = true
			set.OIDC.DefaultUserRoleID = null.NewInt(2, true)
			set.OIDC.Roles = []models.OIDCRoleMapping{tc.mapping}
			err := ValidateSettings(set, []auth.Role{{ID: 2}}, []auth.ListRole{{ID: 10}})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateSettingsAutoCreationStillRequiresDefault(t *testing.T) {
	var set models.Settings
	set.OIDC.AutoCreateUsers = true
	if err := ValidateSettings(set, []auth.Role{{ID: 2}}, nil); err == nil {
		t.Fatal("auto-creation without a default must fail even when synchronization is disabled")
	}
}
