// Package account is a typed client for the Account API on an app's API domain. It works with
// account, instance and install keys; each key type can call the operations its permissions allow.
package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	appsaccountapi "github.com/clorhq/apps/api/accountgen"
	"github.com/clorhq/apps/model"
)

// Account API resources, re-exported so callers need not import generated code.
type (
	Instance        = appsaccountapi.Instance
	InstanceSummary = appsaccountapi.InstanceSummary
	InstanceReport  = appsaccountapi.InstanceReport
	Plan            = appsaccountapi.Plan
	PlanChange      = appsaccountapi.PlanChange
	PlanPreview     = appsaccountapi.PlanPreview
	Invoice         = appsaccountapi.Invoice
	Team            = appsaccountapi.Team
	TeamUpdate      = appsaccountapi.TeamUpdate
	BillingDetails  = appsaccountapi.BillingDetails
	BillingAddress  = appsaccountapi.BillingAddress
	Key             = appsaccountapi.Key
	Member          = appsaccountapi.Member
	Invitation      = appsaccountapi.Invitation
	Role            = appsaccountapi.Role
	InstanceMode    = appsaccountapi.InstanceMode
	ModeSwitch      = appsaccountapi.ModeSwitch
)

// Instance modes. Managed instances run the launcher; offline instances use license files.
const (
	InstanceModeManaged = appsaccountapi.InstanceModeManaged
	InstanceModeOffline = appsaccountapi.InstanceModeOffline
)

// Team roles. Admins do everything; billing members handle invoices, cards and credit.
const (
	RoleAdmin   = appsaccountapi.RoleAdmin
	RoleBilling = appsaccountapi.RoleBilling
)

// requestTimeout bounds each Account API request.
const requestTimeout = 30 * time.Second

// Error is an Account API failure with its HTTP status and message.
type Error struct {
	Status  int
	Message string
}

// Error formats the status and message.
func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("request failed with status %d", e.Status)
	}
	return fmt.Sprintf("request failed with status %d. %s", e.Status, model.SentenceCase(e.Message))
}

// Client calls the Account API with one key.
type Client struct {
	origin string
	key    string
	http   *http.Client
	api    *appsaccountapi.Client
}

// NewClientArgs selects the API origin and key. On an instance both default to the managed
// APPS_SERVICE_ORIGIN and APPS_INSTANCE_API_KEY environment values.
type NewClientArgs struct {
	// APIOrigin is the app's API domain origin, such as https://api.example.com.
	APIOrigin string
	Key       string
	// HTTPClient is optional.
	HTTPClient *http.Client
}

// NewClient validates the origin and key and returns an Account API client.
func NewClient(args *NewClientArgs) (*Client, error) {
	origin := strings.TrimRight(strings.TrimSpace(args.APIOrigin), "/")
	if origin == "" {
		origin = strings.TrimSpace(os.Getenv(model.EnvironmentServiceOrigin))
	}
	key := strings.TrimSpace(args.Key)
	if key == "" {
		key = strings.TrimSpace(os.Getenv(model.EnvironmentInstanceAPIKey))
	}
	address, err := url.Parse(origin)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.Path != "" || address.User != nil {
		return nil, errors.New("the API origin must be an HTTPS origin such as https://api.example.com")
	}
	if key == "" {
		return nil, errors.New("a key is required")
	}
	// A copy of the caller's client, so its own redirect policy is untouched:
	// every request here carries the account key or an identity token, which
	// a redirect would resend to another origin.
	httpClient := &http.Client{Timeout: requestTimeout}
	if args.HTTPClient != nil {
		*httpClient = *args.HTTPClient
	}
	httpClient.CheckRedirect = rejectRedirect
	client := &Client{
		origin: origin,
		key:    key,
		http:   httpClient,
	}
	client.api, err = appsaccountapi.NewClient(
		origin,
		appsaccountapi.WithHTTPClient(httpClient),
		appsaccountapi.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			req.Header.Set(model.HeaderAuthorization, model.BearerPrefix+key)
			return nil
		}),
	)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// APIOrigin returns the API domain origin the client calls.
func (c *Client) APIOrigin() string { return c.origin }

// decodeResponse reads a bounded JSON response into its type or returns an *Error.
func decodeResponse[T any](res *http.Response, err error) (*T, error) {
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(res.Body, model.MaximumJSONSize+1))
	if err := errors.Join(readErr, res.Body.Close()); err != nil {
		return nil, err
	}
	if len(body) > model.MaximumJSONSize {
		return nil, errors.New("response exceeds size limit")
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		failure := &Error{Status: res.StatusCode}
		var message struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &message) == nil {
			failure.Message = message.Message
		}
		return nil, failure
	}
	var document T
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, err
	}
	return &document, nil
}

// collection is a list response.
type collection[T any] struct {
	Items []T `json:"items"`
	Count int `json:"count"`
}

// emptyResponse checks a response that has no body, returning an *Error for failures.
func emptyResponse(res *http.Response, err error) error {
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusNoContent {
		return res.Body.Close()
	}
	_, err = decodeResponse[json.RawMessage](res, nil)
	return err
}

// listResponse decodes a list response into its items.
func listResponse[T any](res *http.Response, err error) ([]T, error) {
	items, err := decodeResponse[collection[T]](res, err)
	if err != nil {
		return nil, err
	}
	return items.Items, nil
}

// ListArgs narrows a list of instances or keys. A nil ListArgs lists everything.
type ListArgs struct {
	// LabelSelector keeps only resources whose labels match, such as "role=backup,!pinned".
	LabelSelector string
}

// labelParameter returns the optional label selector query value.
func labelParameter(args *ListArgs) *string {
	if args == nil {
		return nil
	}
	selector := strings.TrimSpace(args.LabelSelector)
	if selector == "" {
		return nil
	}
	return &selector
}

// ListInstances lists the team's instances of this app, optionally narrowed by args.
func (c *Client) ListInstances(ctx context.Context, args *ListArgs) ([]InstanceSummary, error) {
	return listResponse[InstanceSummary](c.api.ListInstances(ctx, &appsaccountapi.ListInstancesParams{
		Label: labelParameter(args),
	}))
}

// LabelChange removes, then sets labels in one step.
type LabelChange struct {
	Set    map[string]string
	Remove []string
}

// labelChangeBody converts a label change to its request body.
func labelChangeBody(change *LabelChange) appsaccountapi.LabelChange {
	body := appsaccountapi.LabelChange{}
	if len(change.Set) > 0 {
		set := appsaccountapi.Labels(change.Set)
		body.Set = &set
	}
	if len(change.Remove) > 0 {
		body.Remove = &change.Remove
	}
	return body
}

// UpdateInstanceLabels removes, then sets labels on an instance.
func (c *Client) UpdateInstanceLabels(ctx context.Context, instanceID string, change *LabelChange) (*Instance, error) {
	return decodeResponse[Instance](c.api.UpdateInstanceLabels(ctx, instanceID, labelChangeBody(change)))
}

// UpdateKeyLabels removes, then sets labels on a key.
func (c *Client) UpdateKeyLabels(ctx context.Context, keyID string, change *LabelChange) (*Key, error) {
	return decodeResponse[Key](c.api.UpdateKeyLabels(ctx, keyID, labelChangeBody(change)))
}

// ShowInstance shows one instance with its plan, license, readiness and report.
func (c *Client) ShowInstance(ctx context.Context, instanceID string) (*Instance, error) {
	return decodeResponse[Instance](c.api.ShowInstance(ctx, instanceID))
}

// ShowCurrentInstance shows the instance an instance key belongs to.
func (c *Client) ShowCurrentInstance(ctx context.Context) (*Instance, error) {
	return decodeResponse[Instance](c.api.ShowCurrentInstance(ctx))
}

// ReportArgs is the application's short status report about its own instance.
type ReportArgs struct {
	ReportedStatus     string
	UpgradeRecommended bool
	UpgradeReason      string
}

// ReportCurrentInstance replaces the instance key's own status report.
func (c *Client) ReportCurrentInstance(ctx context.Context, args *ReportArgs) (*InstanceReport, error) {
	return decodeResponse[InstanceReport](c.api.ReportCurrentInstance(ctx, appsaccountapi.InstanceReportRequest{
		ReportedStatus:     &args.ReportedStatus,
		UpgradeRecommended: &args.UpgradeRecommended,
		UpgradeReason:      &args.UpgradeReason,
	}))
}

// ListPlans lists the plans the team can select.
func (c *Client) ListPlans(ctx context.Context) ([]Plan, error) {
	return listResponse[Plan](c.api.ListPlans(ctx))
}

// ClaimArgs claims an unclaimed instance from its claim URL.
type ClaimArgs struct {
	InstanceID string
	ClaimToken string
	Name       string
	// PlanID is optional and defaults to the app's free plan.
	PlanID string
}

// ClaimInstance claims an unclaimed instance for the key's team.
func (c *Client) ClaimInstance(ctx context.Context, args *ClaimArgs) (*Instance, error) {
	body := appsaccountapi.ClaimInstanceJSONRequestBody{
		InstanceID: args.InstanceID,
		ClaimToken: args.ClaimToken,
		Name:       args.Name,
	}
	if args.PlanID != "" {
		body.PlanID = &args.PlanID
	}
	return decodeResponse[Instance](c.api.ClaimInstance(ctx, body))
}

// ConfigureArgs are an instance's update settings. ExpectedRevision is the instance's current revision.
type ConfigureArgs struct {
	ExpectedRevision int64
	UpdateMode       string
	Channel          string
	UpdateVersion    string
	Timezone         string
	MaintenanceStart int
	MaintenanceEnd   int
	// Update requests the newest release of the channel now.
	Update bool
}

// ConfigureInstance saves update settings for one instance.
func (c *Client) ConfigureInstance(ctx context.Context, instanceID string, args *ConfigureArgs) (*Instance, error) {
	return decodeResponse[Instance](c.api.ConfigureInstance(ctx, instanceID, appsaccountapi.ConfigureInstanceJSONRequestBody{
		ExpectedRevision: args.ExpectedRevision,
		UpdateMode:       appsaccountapi.ConfigureInstanceJSONBodyUpdateMode(args.UpdateMode),
		Channel:          args.Channel,
		UpdateVersion:    &args.UpdateVersion,
		Timezone:         args.Timezone,
		MaintenanceStart: args.MaintenanceStart,
		MaintenanceEnd:   args.MaintenanceEnd,
		Update:           &args.Update,
	}))
}

// RevokeInstance permanently removes an instance.
func (c *Client) RevokeInstance(ctx context.Context, instanceID string) (*Instance, error) {
	return decodeResponse[Instance](c.api.RevokeInstance(ctx, instanceID))
}

// ChangePlan applies the latest plan choice. A payment_required result continues at
// PaymentURL; choosing a free plan cancels at the end of the paid period, and choosing the
// current plan keeps it. The promo code applies only when the change starts a subscription.
func (c *Client) ChangePlan(ctx context.Context, instanceID, planID, promoCode string) (*PlanChange, error) {
	body := appsaccountapi.ChangeInstancePlanJSONRequestBody{PlanID: planID}
	if promoCode != "" {
		body.PromoCode = &promoCode
	}
	return decodeResponse[PlanChange](c.api.ChangeInstancePlan(ctx, instanceID, body))
}

// PreviewPlan reports what changing to a plan would do without changing anything.
func (c *Client) PreviewPlan(ctx context.Context, instanceID, planID string) (*PlanPreview, error) {
	return decodeResponse[PlanPreview](c.api.PreviewInstancePlan(ctx, instanceID, &appsaccountapi.PreviewInstancePlanParams{Plan: planID}))
}

// ShowTeam shows the key's team: its name, slug and billing details.
func (c *Client) ShowTeam(ctx context.Context) (*Team, error) {
	return decodeResponse[Team](c.api.ShowTeam(ctx))
}

// UpdateTeam changes the team name and replaces billing details. Nil fields are unchanged.
func (c *Client) UpdateTeam(ctx context.Context, update *TeamUpdate) (*Team, error) {
	return decodeResponse[Team](c.api.UpdateTeam(ctx, *update))
}

// Members are a team's members, owner first, and its pending invitations.
type Members struct {
	Items       []Member     `json:"items"`
	Count       int          `json:"count"`
	Invitations []Invitation `json:"invitations"`
}

// ListMembers lists the team's members and pending invitations.
func (c *Client) ListMembers(ctx context.Context) (*Members, error) {
	return decodeResponse[Members](c.api.ListMembers(ctx))
}

// InviteMember invites an email address to the team with a role and emails the link.
func (c *Client) InviteMember(ctx context.Context, email string, role Role) (*Invitation, error) {
	return decodeResponse[Invitation](c.api.InviteMember(ctx, appsaccountapi.InviteMemberJSONRequestBody{
		Email: email,
		Role:  role,
	}))
}

// RevokeInvitation revokes a pending invitation.
func (c *Client) RevokeInvitation(ctx context.Context, invitationID string) error {
	return emptyResponse(c.api.RevokeInvitation(ctx, invitationID))
}

// ChangeMemberRole changes a member's role.
func (c *Client) ChangeMemberRole(ctx context.Context, memberID string, role Role) (*Member, error) {
	return decodeResponse[Member](c.api.ChangeMemberRole(ctx, memberID, appsaccountapi.ChangeMemberRoleJSONRequestBody{
		Role: role,
	}))
}

// RemoveMember removes a member from the team and revokes the account keys they created.
func (c *Client) RemoveMember(ctx context.Context, memberID string) error {
	return emptyResponse(c.api.RemoveMember(ctx, memberID))
}

// BillingPortal returns a hosted billing portal URL.
func (c *Client) BillingPortal(ctx context.Context) (string, error) {
	result, err := decodeResponse[struct {
		URL string `json:"url"`
	}](c.api.CreateBillingPortal(ctx))
	if err != nil {
		return "", err
	}
	return result.URL, nil
}

// ListInvoices lists the team's most recent invoices, newest first, with hosted page and PDF links.
func (c *Client) ListInvoices(ctx context.Context) ([]Invoice, error) {
	return listResponse[Invoice](c.api.ListInvoices(ctx))
}

// CreateCardCheckout returns a hosted card form URL. The card it saves becomes the default
// for invoices and renewals, and the person returns to the team's Billing page.
func (c *Client) CreateCardCheckout(ctx context.Context) (string, error) {
	result, err := decodeResponse[struct {
		URL string `json:"url"`
	}](c.api.CreateCardCheckout(ctx))
	if err != nil {
		return "", err
	}
	return result.URL, nil
}

// ListKeys lists account and install keys, optionally narrowed by args.
func (c *Client) ListKeys(ctx context.Context, args *ListArgs) ([]Key, error) {
	return listResponse[Key](c.api.ListKeys(ctx, &appsaccountapi.ListKeysParams{
		Label: labelParameter(args),
	}))
}

// CreateKeyArgs describes a new account or install key.
type CreateKeyArgs struct {
	// Type is account or install.
	Type string
	Name string
	// Expires is optional; keys never expire by default.
	Expires   *time.Time
	Reusable  bool
	Ephemeral bool
	// Labels organize the key; instances installed with an install key copy them.
	Labels map[string]string
}

// CreatedKey is a new key with its one-time token.
type CreatedKey struct {
	Key   Key    `json:"key"`
	Token string `json:"token"`
}

// CreateKey creates a key and returns its token, which is shown only once.
func (c *Client) CreateKey(ctx context.Context, args *CreateKeyArgs) (*CreatedKey, error) {
	body := appsaccountapi.CreateKeyJSONRequestBody{
		Type:      appsaccountapi.CreateKeyJSONBodyType(args.Type),
		Name:      &args.Name,
		Expires:   args.Expires,
		Reusable:  &args.Reusable,
		Ephemeral: &args.Ephemeral,
	}
	if len(args.Labels) > 0 {
		labels := appsaccountapi.Labels(args.Labels)
		body.Labels = &labels
	}
	return decodeResponse[CreatedKey](c.api.CreateKey(ctx, body))
}

// RevokeKey revokes a key.
func (c *Client) RevokeKey(ctx context.Context, keyID string) (*Key, error) {
	return decodeResponse[Key](c.api.RevokeKey(ctx, keyID))
}

// IdentityToken exchanges the client's account key for an identity token for one instance of this
// app, bound to a nonce from that instance. The key goes only to the API domain.
func (c *Client) IdentityToken(ctx context.Context, instanceID, nonce string) (string, error) {
	parameters := url.Values{
		"grant_type":         {model.OAuthTokenExchangeGrant},
		"subject_token":      {c.key},
		"subject_token_type": {model.OAuthAccessTokenType},
		"audience":           {instanceID},
		"nonce":              {nonce},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+model.RouteIdentityToken, strings.NewReader(parameters.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set(model.HeaderContentType, model.FormMediaType)
	result, err := decodeResponse[struct {
		IDToken string `json:"id_token"`
	}](c.http.Do(req))
	if err != nil {
		return "", err
	}
	return result.IDToken, nil
}

// CreateOfflineInstance adds an offline server to the key's team. The name is optional.
func (c *Client) CreateOfflineInstance(ctx context.Context, name string) (*Instance, error) {
	body := appsaccountapi.CreateOfflineInstanceJSONRequestBody{}
	if name = strings.TrimSpace(name); name != "" {
		body.Name = &name
	}
	return decodeResponse[Instance](c.api.CreateOfflineInstance(ctx, body))
}

// DownloadInstanceLicense returns the instance's current armored license file.
func (c *Client) DownloadInstanceLicense(ctx context.Context, instanceID string) (string, error) {
	return textResponse(c.api.DownloadInstanceLicense(ctx, instanceID))
}

// RenewInstanceLicense starts a new free term and returns its license file. A stale
// expected revision returns the current license file unchanged.
func (c *Client) RenewInstanceLicense(ctx context.Context, instanceID string, expectedLicenseRevision int64) (string, error) {
	return textResponse(c.api.RenewInstanceLicense(ctx, instanceID, appsaccountapi.RenewInstanceLicenseJSONRequestBody{
		ExpectedLicenseRevision: expectedLicenseRevision,
	}))
}

// SwitchInstanceMode switches an instance between managed and offline. Switching to
// managed returns the one-time install command that attaches a launcher.
func (c *Client) SwitchInstanceMode(ctx context.Context, instanceID string, mode InstanceMode) (*ModeSwitch, error) {
	return decodeResponse[ModeSwitch](c.api.SwitchInstanceMode(ctx, instanceID, appsaccountapi.SwitchInstanceModeJSONRequestBody{
		Mode: mode,
	}))
}

// textResponse reads a bounded text response or returns an *Error.
func textResponse(res *http.Response, err error) (string, error) {
	if err != nil {
		return "", err
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		_, err := decodeResponse[json.RawMessage](res, nil)
		return "", err
	}
	body, readErr := io.ReadAll(io.LimitReader(res.Body, model.MaximumJSONSize+1))
	if err := errors.Join(readErr, res.Body.Close()); err != nil {
		return "", err
	}
	if len(body) > model.MaximumJSONSize {
		return "", errors.New("response exceeds size limit")
	}
	return string(body), nil
}

// AddInstanceDomain adds a custom domain to a managed instance.
func (c *Client) AddInstanceDomain(ctx context.Context, instanceID, name string) (*Instance, error) {
	return decodeResponse[Instance](c.api.AddInstanceDomain(ctx, instanceID, appsaccountapi.AddInstanceDomainJSONRequestBody{
		Name: strings.TrimSpace(name),
	}))
}

// RemoveInstanceDomain removes a custom domain from an instance.
func (c *Client) RemoveInstanceDomain(ctx context.Context, instanceID, name string) (*Instance, error) {
	return decodeResponse[Instance](c.api.RemoveInstanceDomain(ctx, instanceID, appsaccountapi.RemoveInstanceDomainJSONRequestBody{
		Name: strings.TrimSpace(name),
	}))
}

// rejectRedirect returns a redirect response instead of following it, so a
// credential in the request never reaches the redirect's target.
func rejectRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
