package core

import (
	"testing"

	"slopdns/web/backend/internal/authz"
	"slopdns/web/pkg/rbac"
)

func TestCanAcceptTransferIntoRequiresTargetOrgAdmin(t *testing.T) {
	bindings := []authz.Binding{
		{ResourceType: rbac.ResourceOrg, ResourceID: "org-a", OrgID: "org-a", Role: rbac.RoleOwner},
		{ResourceType: rbac.ResourceZone, ResourceID: "zone-b", OrgID: "org-b", Role: rbac.RoleAdmin},
	}

	if canAcceptTransferInto(bindings, "org-b") {
		t.Fatal("admin access to a zone must not authorize a transfer into its organization")
	}
	if canAcceptTransferInto(bindings, "org-c") {
		t.Fatal("an unrelated organization role must not authorize the target organization")
	}

	bindings = append(bindings, authz.Binding{
		ResourceType: rbac.ResourceOrg,
		ResourceID:   "org-b",
		OrgID:        "org-b",
		Role:         rbac.RoleAdmin,
	})
	if !canAcceptTransferInto(bindings, "org-b") {
		t.Fatal("target organization admins must be allowed to accept a transfer")
	}
}
