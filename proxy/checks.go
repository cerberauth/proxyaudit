// Package proxy is a detection engine for testing whether a reverse proxy
// or API gateway is securely configured. It builds on harnessx for check
// orchestration/dependency wiring and harnessx/checkdef for declarative
// check metadata (CVSS/CWE/OWASP); proxy itself only adds the domain
// layer: the proxy-specific ScanContext (in the scanctx subpackage), the
// individual checks under checks/, and AllChecks, which registers them.
package proxy

import (
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	configexposure "github.com/cerberauth/proxyaudit/proxy/checks/disclosure/config_exposure"
	directorylisting "github.com/cerberauth/proxyaudit/proxy/checks/disclosure/directory_listing"
	exposedmanagement "github.com/cerberauth/proxyaudit/proxy/checks/disclosure/exposed_management"
	verboseerrors "github.com/cerberauth/proxyaudit/proxy/checks/disclosure/verbose_errors"
	contenttypeoptions "github.com/cerberauth/proxyaudit/proxy/checks/headers/content_type_options"
	cookieflags "github.com/cerberauth/proxyaudit/proxy/checks/headers/cookie_flags"
	"github.com/cerberauth/proxyaudit/proxy/checks/headers/csp"
	frameoptions "github.com/cerberauth/proxyaudit/proxy/checks/headers/frame_options"
	permissionspolicy "github.com/cerberauth/proxyaudit/proxy/checks/headers/permissions_policy"
	referrerpolicy "github.com/cerberauth/proxyaudit/proxy/checks/headers/referrer_policy"
	serverbanner "github.com/cerberauth/proxyaudit/proxy/checks/headers/server_banner"
	aclbypass "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/acl_bypass"
	forwardedconsistency "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/forwarded_consistency"
	hostheaderinjection "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/host_header_injection"
	trueclientip "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/true_client_ip"
	vhostconfusion "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/vhost_confusion"
	xforwardedfor "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/x_forwarded_for"
	xforwardedhost "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/x_forwarded_host"
	xrealip "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/x_real_ip"
	"github.com/cerberauth/proxyaudit/proxy/checks/tls/certificate"
	cipherstrength "github.com/cerberauth/proxyaudit/proxy/checks/tls/cipher_strength"
	"github.com/cerberauth/proxyaudit/proxy/checks/tls/hsts"
	httpsredirect "github.com/cerberauth/proxyaudit/proxy/checks/tls/https_redirect"
	protocolversion "github.com/cerberauth/proxyaudit/proxy/checks/tls/protocol_version"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

// AllChecks returns every v0.1 proxy check (shared probes first, in
// dependency order) along with their CheckDef metadata (CVSS/CWE/OWASP),
// keyed by CheckID since harnessx.Check itself doesn't carry that
// metadata. Callers register the returned checks on a harnessx.Engine
// directly; AllChecks itself has no CLI or reporting dependencies.
func AllChecks() ([]harnessx.Check, map[harnessx.CheckID]checkdef.CheckDef) {
	checks := []harnessx.Check{
		// Shared probes other checks depend on.
		probebase.HTTPFetchCheck,
		probebase.TLSInfoCheck,

		// TLS / Transport.
		protocolversion.Check,
		cipherstrength.Check,
		certificate.Check,
		httpsredirect.Check,
		hsts.Check,

		// HTTP Security Headers.
		csp.Check,
		frameoptions.Check,
		contenttypeoptions.Check,
		referrerpolicy.Check,
		permissionspolicy.Check,
		serverbanner.Check,
		cookieflags.Check,

		// Client-IP & Header Trust Boundary.
		xforwardedfor.Check,
		xrealip.Check,
		trueclientip.Check,
		xforwardedhost.Check,
		hostheaderinjection.Check,
		vhostconfusion.Check,
		forwardedconsistency.Check,
		aclbypass.Check,

		// Information Disclosure & Exposed Management Interfaces.
		exposedmanagement.Check,
		directorylisting.Check,
		configexposure.Check,
		verboseerrors.Check,
	}

	defs := map[harnessx.CheckID]checkdef.CheckDef{
		protocolversion.Check.ID: protocolversion.Def,
		cipherstrength.Check.ID:  cipherstrength.Def,
		certificate.Check.ID:     certificate.Def,
		httpsredirect.Check.ID:   httpsredirect.Def,
		hsts.Check.ID:            hsts.Def,

		csp.Check.ID:                csp.Def,
		frameoptions.Check.ID:       frameoptions.Def,
		contenttypeoptions.Check.ID: contenttypeoptions.Def,
		referrerpolicy.Check.ID:     referrerpolicy.Def,
		permissionspolicy.Check.ID:  permissionspolicy.Def,
		serverbanner.Check.ID:       serverbanner.Def,
		cookieflags.Check.ID:        cookieflags.Def,

		xforwardedfor.Check.ID:        xforwardedfor.Def,
		xrealip.Check.ID:              xrealip.Def,
		trueclientip.Check.ID:         trueclientip.Def,
		xforwardedhost.Check.ID:       xforwardedhost.Def,
		hostheaderinjection.Check.ID:  hostheaderinjection.Def,
		vhostconfusion.Check.ID:       vhostconfusion.Def,
		forwardedconsistency.Check.ID: forwardedconsistency.Def,
		aclbypass.Check.ID:            aclbypass.Def,

		exposedmanagement.Check.ID: exposedmanagement.Def,
		directorylisting.Check.ID:  directorylisting.Def,
		configexposure.Check.ID:    configexposure.Def,
		verboseerrors.Check.ID:     verboseerrors.Def,
	}

	return checks, defs
}
