package cloudblast

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxHostnameLen = 191
	minSSHKeys     = 1
	maxSSHKeys     = 20
	maxListPages   = 1000
)

// IPAddress is one address attached to a server.
type IPAddress struct {
	Address  string `json:"address"`
	Type     string `json:"type"`
	Gateway  string `json:"gateway"`
	CIDR     string `json:"cidr"`
	RDNS     string `json:"rdns"`
	Reserved bool   `json:"reserved"`
}

// Folder is the read-only folder reference returned by GET /servers/{uuid}.
type Folder struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Server is a CloudBlast VM.
type Server struct {
	ID           int         `json:"id"`
	UUID         string      `json:"uuid"`
	UUIDShort    string      `json:"uuid_short"`
	Hostname     string      `json:"hostname"`
	Name         string      `json:"name"`
	Status       *string     `json:"status"`
	State        string      `json:"state"`
	ServerStatus *string     `json:"server_status"`
	PlanID       int         `json:"plan_id"`
	LocationID   int         `json:"location_id"`
	TemplateSlug string      `json:"template_slug"`
	SSHKeyIDs    []int       `json:"ssh_key_ids"`
	IPAddresses  []IPAddress `json:"ip_addresses"`
	Folder       *Folder     `json:"folder"`
	CreatedAt    string      `json:"created_at"`
}

// ServerStatus is the payload of GET /servers/{uuid}/status.
type ServerStatus struct {
	State        string  `json:"state"`
	ServerStatus *string `json:"server_status"`
}

// Credentials is the payload of GET /servers/{uuid}/credentials.
type Credentials struct {
	Username       string `json:"username"`
	RootPassword   string `json:"root_password"`
	PasswordStatus string `json:"password_status"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`
}

// CreateServerRequest is the POST /servers body.
type CreateServerRequest struct {
	PlanID       int    `json:"plan_id"`
	LocationID   int    `json:"location_id"`
	TemplateSlug string `json:"template_slug"`
	Hostname     string `json:"hostname"`
	SSHKeyIDs    []int  `json:"ssh_key_ids"`
}

// Validate checks the CloudBlast create constraints before any request is sent.
func (r CreateServerRequest) Validate() error {
	if r.PlanID <= 0 {
		return errors.New("cloudblast-plan-id must be > 0")
	}
	if r.LocationID <= 0 {
		return errors.New("cloudblast-location-id must be > 0")
	}
	if strings.TrimSpace(r.TemplateSlug) == "" {
		return errors.New("cloudblast-template-slug is required")
	}
	if strings.TrimSpace(r.Hostname) == "" {
		return errors.New("cloudblast hostname is required")
	}
	if len(r.Hostname) > maxHostnameLen {
		return fmt.Errorf("cloudblast hostname must be at most %d characters", maxHostnameLen)
	}
	if len(r.SSHKeyIDs) < minSSHKeys || len(r.SSHKeyIDs) > maxSSHKeys {
		return fmt.Errorf("cloudblast ssh_key_ids must contain between %d and %d keys", minSSHKeys, maxSSHKeys)
	}
	return nil
}

// CreateServer creates a VM. It is not retried automatically: callers must
// reconcile by hostname before retrying (the API has no idempotency key).
func (c *Client) CreateServer(ctx context.Context, req CreateServerRequest) (*Server, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	raw, _, err := c.do(ctx, http.MethodPost, "/servers", nil, req)
	if err != nil {
		return nil, err
	}
	return decodeOne[Server](raw)
}

// ListServers returns every server in the account, following meta.last_page.
func (c *Client) ListServers(ctx context.Context) ([]Server, error) {
	var all []Server
	for page := 1; page <= maxListPages; page++ {
		query := url.Values{"page": []string{strconv.Itoa(page)}}
		raw, meta, err := c.do(ctx, http.MethodGet, "/servers", query, nil)
		if err != nil {
			return nil, err
		}
		servers, err := decodeMany[Server](raw)
		if err != nil {
			return nil, err
		}
		all = append(all, servers...)
		if meta == nil || meta.LastPage <= page || len(servers) == 0 {
			return all, nil
		}
	}
	return nil, fmt.Errorf("cloudblast: server list exceeded %d pages", maxListPages)
}

// GetServer returns one server by uuid.
func (c *Client) GetServer(ctx context.Context, uuid string) (*Server, error) {
	raw, _, err := c.do(ctx, http.MethodGet, "/servers/"+url.PathEscape(uuid), nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeOne[Server](raw)
}

// GetServerStatus returns the hypervisor state and application status.
func (c *Client) GetServerStatus(ctx context.Context, uuid string) (*ServerStatus, error) {
	raw, _, err := c.do(ctx, http.MethodGet, "/servers/"+url.PathEscape(uuid)+"/status", nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeOne[ServerStatus](raw)
}

// GetServerCredentials returns the SSH address and root password metadata.
func (c *Client) GetServerCredentials(ctx context.Context, uuid string) (*Credentials, error) {
	raw, _, err := c.do(ctx, http.MethodGet, "/servers/"+url.PathEscape(uuid)+"/credentials", nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeOne[Credentials](raw)
}

// DeleteServer deletes a server. A missing server is treated as success.
// CloudBlast expects keep_ips to be a comma-separated list of the server's own
// addresses (not a boolean), so when keepIPs is false the parameter is omitted.
func (c *Client) DeleteServer(ctx context.Context, uuid string, keepIPs bool) error {
	var query url.Values
	if keepIPs {
		server, err := c.GetServer(ctx, uuid)
		if err != nil {
			if IsNotFound(err) {
				return nil
			}
			return err
		}
		if addresses := serverAddresses(server); len(addresses) > 0 {
			query = url.Values{"keep_ips": []string{strings.Join(addresses, ",")}}
		}
	}
	_, _, err := c.do(ctx, http.MethodDelete, "/servers/"+url.PathEscape(uuid), query, nil)
	if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

// serverAddresses returns unique non-empty addresses in API order.
func serverAddresses(server *Server) []string {
	if server == nil {
		return nil
	}
	seen := make(map[string]bool, len(server.IPAddresses))
	addresses := make([]string, 0, len(server.IPAddresses))
	for _, addr := range server.IPAddresses {
		if addr.Address == "" || seen[addr.Address] {
			continue
		}
		seen[addr.Address] = true
		addresses = append(addresses, addr.Address)
	}
	return addresses
}

// validActions is the power action surface documented for POST /servers/{uuid}/actions.
var validActions = map[string]bool{
	"start": true, "shutdown": true, "restart": true,
	"reset": true, "kill": true, "suspend": true, "resume": true,
}

// ServerAction asks CloudBlast to perform a power action. It returns once the
// action is accepted; callers poll /status for the resulting state.
func (c *Client) ServerAction(ctx context.Context, uuid, action string) error {
	if !validActions[action] {
		return fmt.Errorf("cloudblast: unsupported server action %q", action)
	}
	_, _, err := c.do(ctx, http.MethodPost, "/servers/"+url.PathEscape(uuid)+"/actions", nil, map[string]string{"action": action})
	return err
}

// SelectServerByHostname resolves a hostname to an existing server. It returns
// (server, false, nil) for exactly one match, (nil, true, nil) when no server
// exists (create is safe), and an error when more than one matches: the driver
// must never guess which VM to adopt.
func SelectServerByHostname(servers []Server, hostname string) (*Server, bool, error) {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return nil, false, errors.New("cloudblast: hostname is required for reconcile")
	}
	var matches []Server
	for i := range servers {
		if servers[i].Hostname == hostname {
			matches = append(matches, servers[i])
		}
	}
	switch len(matches) {
	case 0:
		return nil, true, nil
	case 1:
		return &matches[0], false, nil
	default:
		return nil, false, fmt.Errorf("cloudblast: found %d servers with hostname %q; refusing to adopt one", len(matches), hostname)
	}
}

// IPv4 returns the first IPv4 address of the server, if any.
func (s *Server) IPv4() string {
	for _, addr := range s.IPAddresses {
		if addr.Type == "ipv4" && addr.Address != "" {
			return addr.Address
		}
	}
	return ""
}
