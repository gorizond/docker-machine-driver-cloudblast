package cloudblast

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

func statusHint(status int, code string) string {
	switch status {
	case http.StatusUnauthorized:
		return "невалидный API-токен"
	case http.StatusForbidden:
		if code == "IP_NOT_ALLOWED" {
			return "IP не в whitelist аккаунта CloudBlast"
		}
		return "доступ к CloudBlast запрещён"
	case http.StatusPaymentRequired:
		return "недостаточно средств на аккаунте CloudBlast"
	case http.StatusNotFound:
		return "сервер не найден"
	case http.StatusConflict:
		return "конфликт состояния сервера CloudBlast"
	case http.StatusUnprocessableEntity:
		return "ошибка валидации запроса CloudBlast"
	case http.StatusTooManyRequests:
		return "лимит запросов CloudBlast"
	default:
		if status >= 500 {
			return "временная ошибка CloudBlast"
		}
		return ""
	}
}

func shouldRetryStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

func (c *Client) backoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		if retryAfter > maxRetryAfter {
			return maxRetryAfter
		}
		return retryAfter
	}
	delay := c.RetryBackoff * time.Duration(1<<(attempt-1))
	if delay > maxRetryAfter {
		return maxRetryAfter
	}
	return delay
}

func retryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if secs, err := strconv.Atoi(value); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}
