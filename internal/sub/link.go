package sub

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"privatevpn/internal/xray"
)

// Link is one VLESS Reality URI Happ can import from a subscription body.
type Link struct {
	Name    string
	UUID    string
	Address string
	Reality xray.Reality
}

// VLESS returns a vless:// URI for this device.
func (l Link) VLESS() (string, error) {
	if err := l.Reality.Validate(); err != nil {
		return "", err
	}
	if l.UUID == "" || l.Address == "" {
		return "", fmt.Errorf("subscription target")
	}
	host := net.JoinHostPort(l.Address, strconv.Itoa(l.Reality.Port))
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("flow", "xtls-rprx-vision")
	q.Set("security", "reality")
	q.Set("sni", l.Reality.ServerNames[0])
	q.Set("fp", l.Reality.Fingerprint)
	q.Set("pbk", l.Reality.PublicKey)
	q.Set("sid", l.Reality.ShortIDs[0])
	q.Set("type", "tcp")
	q.Set("headerType", "none")
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(l.UUID),
		Host:     host,
		RawQuery: q.Encode(),
		Fragment: l.Name,
	}
	return u.String(), nil
}

// Body is the Happ subscription document. Directives sit above the URI
// so a refresh keeps sending the device id.
func (l Link) Body() (string, error) {
	link, err := l.VLESS()
	if err != nil {
		return "", err
	}
	title := l.Name
	if len(title) > 25 {
		title = title[:25]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#subscription-always-hwid-enable: 1\n")
	fmt.Fprintf(&b, "#profile-update-interval: 12\n")
	fmt.Fprintf(&b, "#profile-title: %s\n", title)
	fmt.Fprintf(&b, "%s\n", link)
	return b.String(), nil
}

// URL joins the panel base URL and a device token.
func URL(publicBase, token string) string {
	return strings.TrimRight(publicBase, "/") + "/s/" + token
}
