package rbac

import "testing"

func TestZoneBindingStaysScopedToItsZone(t *testing.T) {
	bindings := []Binding{{
		ResourceType: ResourceZone,
		ResourceID:   "zone-a",
		OrgID:        "org-a",
		Role:         RoleAdmin,
	}}

	tests := []struct {
		name string
		res  Resource
		want Role
	}{
		{
			name: "matching zone",
			res:  Resource{Type: ResourceZone, ID: "zone-a", OrgID: "org-a"},
			want: RoleAdmin,
		},
		{
			name: "organization",
			res:  Resource{Type: ResourceOrg, ID: "org-a", OrgID: "org-a"},
			want: RoleNone,
		},
		{
			name: "different zone",
			res:  Resource{Type: ResourceZone, ID: "zone-b", OrgID: "org-a"},
			want: RoleNone,
		},
		{
			name: "service account",
			res:  Resource{Type: ResourceServiceAccount, ID: "sa-a", OrgID: "org-a"},
			want: RoleNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EffectiveRole(tt.res, bindings); got != tt.want {
				t.Fatalf("EffectiveRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOrganizationBindingStillAppliesToChildResources(t *testing.T) {
	bindings := []Binding{{
		ResourceType: ResourceOrg,
		ResourceID:   "org-a",
		OrgID:        "org-a",
		Role:         RoleAdmin,
	}}
	res := Resource{Type: ResourceZone, ID: "zone-a", OrgID: "org-a"}

	if got := EffectiveRole(res, bindings); got != RoleAdmin {
		t.Fatalf("EffectiveRole() = %v, want %v", got, RoleAdmin)
	}
}
