package cloudblast

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultAPIBaseURL is the public CloudBlast API V2 endpoint.
	DefaultAPIBaseURL = "https://console.cloudblast.io/api/v2"
	// userAgent is sent on every request so CloudBlast can identify the driver.
	userAgent = "docker-machine-driver-cloudblast"

	defaultTimeout      = 60 * time.Second
	defaultMaxAttempts  = 3
	defaultRetryBackoff = 500 * time.Millisecond
	maxRetryAfter       = 60 * time.Second
	maxResponseBytes    = 4 << 20
)

// APIError is a non-2xx response from CloudBlast. It never carries the token.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	Details    json.RawMessage
}

func (e *APIError) Error() string {
	msg := e.Message
	if hint := statusHint(e.StatusCode, e.Code); hint != "" {
		if msg == "" {
			msg = hint
		} else if !strings.Contains(msg, hint) {
			msg = hint + ": " + msg
		}
	}
	if msg == "" {
		msg = "request failed"
	}
	if e.Code != "" {
		return fmt.Sprintf("cloudblast: %s (HTTP %d, %s)", msg, e.StatusCode, e.Code)
	}
	return fmt.Sprintf("cloudblast: %s (HTTP %d)", msg, e.StatusCode)
}

// IsNotFound reports whether err is a CloudBlast 404 response.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// IsUnauthorized reports whether err is a CloudBlast 401/403 response.
func IsUnauthorized(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden)
}

// Meta is the pagination envelope returned by list endpoints.
type Meta struct {
	CurrentPage int `json:"current_page"`
	LastPage    int `json:"last_page"`
	PerPage     int `json:"per_page"`
	Total       int `json:"total"`
}

type errorBody struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Details json.RawMessage `json:"details"`
}

type envelope struct {
	Data  json.RawMessage `json:"data"`
	Meta  *Meta           `json:"meta"`
	Error *errorBody      `json:"error"`
}

// Client is a minimal CloudBlast API V2 client. The zero value is not usable;
// use NewClient.
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
	UserAgent  string
	// MaxAttempts includes the first attempt (default 3).
	MaxAttempts int
	// RetryBackoff is the base exponential backoff for 5xx responses.
	RetryBackoff time.Duration

	sleep func(time.Duration)
}

// NewClient builds a CloudBlast client. insecure disables TLS verification and
// is meant for test installations only.
func NewClient(baseURL, token string, insecure bool) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultAPIBaseURL
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test contour only
	}
	return &Client{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		Token:        token,
		HTTPClient:   &http.Client{Timeout: defaultTimeout, Transport: transport},
		UserAgent:    userAgent,
		MaxAttempts:  defaultMaxAttempts,
		RetryBackoff: defaultRetryBackoff,
		sleep:        time.Sleep,
	}
}

// do executes a request and returns the unwrapped "data" payload plus meta.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (json.RawMessage, *Meta, error) {
	if c.HTTPClient == nil {
		return nil, nil, errors.New("cloudblast: client is not initialized")
	}
	if c.sleep == nil {
		c.sleep = time.Sleep
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaultMaxAttempts
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = defaultRetryBackoff
	}

	endpoint := c.BaseURL + "/" + strings.TrimLeft(path, "/")
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, nil, fmt.Errorf("cloudblast: encode request body: %w", err)
		}
	}

	retryableMethod := method == http.MethodGet || method == http.MethodDelete || method == http.MethodHead
	var lastErr error
	for attempt := 1; attempt <= c.MaxAttempts; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
		if reqErr != nil {
			return nil, nil, fmt.Errorf("cloudblast: build request: %w", reqErr)
		}
		c.setHeaders(req)

		resp, doErr := c.HTTPClient.Do(req)
		if doErr != nil {
			lastErr = fmt.Errorf("cloudblast: %s %s: %w", method, path, doErr)
			if !retryableMethod || attempt == c.MaxAttempts || ctx.Err() != nil {
				return nil, nil, lastErr
			}
			c.sleep(c.backoff(attempt, 0))
			continue
		}

		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("cloudblast: read response: %w", readErr)
			if !retryableMethod || attempt == c.MaxAttempts {
				return nil, nil, lastErr
			}
			c.sleep(c.backoff(attempt, 0))
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if len(bytes.TrimSpace(raw)) == 0 {
				return nil, nil, nil
			}
			return c.unwrap(raw)
		}

		apiErr := parseAPIError(resp.StatusCode, raw)
		lastErr = apiErr
		if !shouldRetryStatus(apiErr.StatusCode) || !retryableMethod || attempt == c.MaxAttempts {
			return nil, nil, apiErr
		}
		c.sleep(c.backoff(attempt, retryAfter(resp.Header.Get("Retry-After"))))
	}
	return nil, nil, lastErr
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
}

func (c *Client) unwrap(raw []byte) (json.RawMessage, *Meta, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// Not an envelope: return the raw body so callers can still decode it.
		return json.RawMessage(raw), nil, nil
	}
	if env.Error != nil {
		return nil, nil, &APIError{
			StatusCode: http.StatusOK,
			Code:       env.Error.Code,
			Message:    env.Error.Message,
			Details:    env.Error.Details,
		}
	}
	if len(env.Data) == 0 {
		return json.RawMessage(raw), env.Meta, nil
	}
	return env.Data, env.Meta, nil
}

func parseAPIError(status int, raw []byte) *APIError {
	apiErr := &APIError{StatusCode: status}
	var env envelope
	if err := json.Unmarshal(raw, &env); err == nil && env.Error != nil {
		apiErr.Code = env.Error.Code
		apiErr.Message = env.Error.Message
		apiErr.Details = env.Error.Details
	}
	if apiErr.Message == "" && len(bytes.TrimSpace(raw)) > 0 {
		text := strings.TrimSpace(string(raw))
		if len(text) > 512 {
			text = text[:512] + "…"
		}
		if !strings.HasPrefix(text, "{") {
			apiErr.Message = text
		}
	}
	return apiErr
}
