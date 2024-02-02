//go:build integration
// +build integration

package saml

import (
	"context"
	"encoding/base64"
	"log"
	"os"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"github.com/determined-ai/determined/master/internal/config"
	"github.com/determined-ai/determined/master/internal/db"
	"github.com/determined-ai/determined/master/internal/user"

	"github.com/determined-ai/determined/master/pkg/etc"
	"github.com/determined-ai/determined/master/pkg/model"

	"github.com/RobotsAndPencils/go-saml"
)

func TestMain(m *testing.M) {
	pgDB, err := db.ResolveTestPostgres()
	if err != nil {
		log.Panicln(err)
	}

	err = db.MigrateTestPostgres(pgDB, "file://../../../static/migrations")
	if err != nil {
		log.Panicln(err)
	}

	err = etc.SetRootPath("../../static/srv")
	if err != nil {
		log.Panicln(err)
	}
	os.Exit(m.Run())
}

func TestSAMLWorkflowAutoProvision(t *testing.T) {
	// First, make sure the mock SAML service is created.
	s := mockService(t, true)
	require.NotNil(t, s)

	ctx := context.Background()

	username := uuid.NewString()
	encodedXML := getUserXML(username, username+"123", []string{"abc", "bcd"})
	u := processXMLUnprovisioned(ctx, t, encodedXML, username, username+"123", s)

	require.True(t, u.Remote)

	groups, err := getUserGroups(ctx, u.ID)
	require.NoError(t, err)
	require.Contains(t, groups, "abc")
	require.Contains(t, groups, "bcd")
	require.Equal(t, len(groups), 3)

	_, err = user.StartSession(ctx, u)
	require.NoError(t, err)

	// test Update User fields based on SAML response
	encodedXML = getUserXML(username, username+"456", []string{"abc"})
	u = processXMLProvisioned(ctx, t, encodedXML, username, username+"456", s)

	require.True(t, u.Remote)

	groups2, err := getUserGroups(ctx, u.ID)
	require.NoError(t, err)
	require.Contains(t, groups2, "abc")
	require.NotContains(t, groups2, "bcd")
	require.Equal(t, len(groups2), 2)

	_, err = user.StartSession(ctx, u)
	require.NoError(t, err)
}

func TestSAMLWorkflowUserNotProvisioned(t *testing.T) {
	// First, make sure the mock SAML service is created.
	s := mockService(t, false)
	require.NotNil(t, s)

	ctx := context.Background()

	username := uuid.NewString()
	encodedXML := getUserXML(username, username+"123", []string{"abc", "bcd"})

	response, err := saml.ParseEncodedResponse(encodedXML)
	require.NoError(t, err)

	userAttr := s.toUserAttributes(response)
	require.Equal(t, username, userAttr.userName)

	_, err = user.ByUsername(ctx, userAttr.userName)
	log.Print(err)
	require.ErrorContains(t, err, "not found")
}

func TestSAMLWorkflowUserProvisioned(t *testing.T) {
	// First, make sure the mock SAML service is created.
	s := mockService(t, true)
	require.NotNil(t, s)

	ctx := context.Background()

	username := uuid.NewString()

	initialUser := &model.User{
		Username: username,
		Active:   true,
	}
	_, err := user.Add(ctx, initialUser, nil)
	require.NoError(t, err)

	encodedXML := getUserXML(username, username+"123", []string{"abc", "bcd"})
	u := processXMLProvisioned(ctx, t, encodedXML, username, username+"123", s)

	require.False(t, u.Remote)

	groups, err := getUserGroups(ctx, u.ID)
	require.NoError(t, err)
	require.Contains(t, groups, "abc")
	require.Contains(t, groups, "bcd")
	require.Equal(t, len(groups), 3)

	_, err = user.StartSession(ctx, u)
	require.NoError(t, err)
}

func mockService(t *testing.T, autoProvision bool) *Service {
	samlConfig := config.SAMLConfig{
		Enabled:                  true,
		Provider:                 "Okta",
		IDPRecipientURL:          "http://127.0.0.1:8081/saml/sso",
		IDPSSOURL:                "https://test-okta/sso/saml",
		IDPSSODescriptorURL:      "http://www.okta.com/test",
		IDPCertPath:              "okta_cert.cert",
		AutoProvisionUsers:       autoProvision,
		GroupsAttributeName:      "groups",
		DisplayNameAttributeName: "disp_name",
	}
	service, err := New(db.SingleDB(), samlConfig)
	if err != nil {
		log.Panicln(err)
	}
	return service
}

func getUserXML(username string, dispName string, groups []string) string {
	resp := saml.NewSignedResponse()
	resp.AddAttribute("userName", username)
	resp.AddAttribute("disp_name", dispName)

	for _, g := range groups {
		resp.AddAttribute("groups", g)
	}

	samlStr, err := resp.String()
	if err != nil {
		log.Panicln(err)
	}
	return base64.StdEncoding.EncodeToString([]byte(samlStr))
}

func processXMLUnprovisioned(ctx context.Context, t *testing.T,
	encodedXML string, username string, dispName string, s *Service,
) *model.User {
	response, err := saml.ParseEncodedResponse(encodedXML)
	require.NoError(t, err)

	userAttr := s.toUserAttributes(response)
	require.Equal(t, username, userAttr.userName)

	_, err = user.ByUsername(ctx, userAttr.userName)
	log.Print(err)
	require.True(t, errors.Is(err, db.ErrNotFound), true)
	u, err := s.provisionUser(ctx, userAttr.userName, userAttr.groups)
	require.NoError(t, err)

	u, err = s.syncUser(ctx, u, userAttr)
	require.NoError(t, err)

	require.Equal(t, dispName, u.DisplayName.String)
	require.Equal(t, username, u.Username)

	require.True(t, u.Active)

	return u
}

func processXMLProvisioned(ctx context.Context, t *testing.T,
	encodedXML string, username string, dispName string, s *Service,
) *model.User {
	response, err := saml.ParseEncodedResponse(encodedXML)
	require.NoError(t, err)

	userAttr := s.toUserAttributes(response)
	require.Equal(t, username, userAttr.userName)

	u, err := user.ByUsername(ctx, userAttr.userName)
	require.NoError(t, err)

	u, err = s.syncUser(ctx, u, userAttr)
	require.NoError(t, err)

	require.Equal(t, dispName, u.DisplayName.String)
	require.Equal(t, username, u.Username)

	require.True(t, u.Active)

	return u
}

func getUserGroups(ctx context.Context, uID model.UserID) ([]string, error) {
	groups := []string{}
	err := db.Bun().NewSelect().TableExpr("user_group_membership AS ug").ColumnExpr("g.group_name").
		Where("ug.user_id = ?", uID).Join("LEFT OUTER JOIN groups g ON g.id = ug.group_id").Scan(ctx, &groups)
	return groups, err
}
