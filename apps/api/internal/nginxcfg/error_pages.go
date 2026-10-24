package nginxcfg

import "strconv"

// ErrorPagesDir is the host-visible directory for default HTML error pages (REQ-PROXY-022).
const ErrorPagesDir = "/data/nginx/error_pages"

// ErrorPagesURIPrefix is the internal location used by error_page redirects.
const ErrorPagesURIPrefix = "/nsp-error/"

// ErrorPagesSnippet returns server-level error_page + internal location (REQ-PROXY-022).
// indent is typically "        " for proxy hosts / default_server.
func ErrorPagesSnippet(indent string) string {
	return ErrorPagesSnippetOpts(indent, 0)
}

// ErrorPagesSnippetOpts is ErrorPagesSnippet with optional Retry-After on 429 (REQ-RATE-005).
// When retryAfterSeconds > 0, 429 uses a named location that sets Retry-After.
func ErrorPagesSnippetOpts(indent string, retryAfterSeconds int) string {
	if indent == "" {
		indent = "        "
	}
	dir := escapeNginxString(ErrorPagesDir)
	var b string
	b += indent + "error_page 403 " + ErrorPagesURIPrefix + "403.html;\n"
	b += indent + "error_page 404 " + ErrorPagesURIPrefix + "404.html;\n"
	if retryAfterSeconds > 0 {
		sec := NormalizeRetryAfterSeconds(retryAfterSeconds, 1)
		b += indent + "error_page 429 =429 @nsp_rl_429;\n"
		b += indent + "location @nsp_rl_429 {\n"
		b += indent + "    internal;\n"
		b += indent + "    default_type text/html;\n"
		b += indent + "    charset utf-8;\n"
		b += indent + "    add_header Retry-After " + strconv.Itoa(sec) + " always;\n"
		b += indent + "    root " + dir + ";\n"
		b += indent + "    try_files /429.html =429;\n"
		b += indent + "}\n"
	} else {
		b += indent + "error_page 429 " + ErrorPagesURIPrefix + "429.html;\n"
	}
	b += indent + "error_page 500 " + ErrorPagesURIPrefix + "500.html;\n"
	b += indent + "error_page 502 " + ErrorPagesURIPrefix + "502.html;\n"
	b += indent + "error_page 503 " + ErrorPagesURIPrefix + "503.html;\n"
	b += indent + "error_page 504 " + ErrorPagesURIPrefix + "504.html;\n"
	b += indent + "location ^~ " + ErrorPagesURIPrefix + " {\n"
	b += indent + "    alias " + dir + "/;\n"
	b += indent + "    internal;\n"
	b += indent + "    default_type text/html;\n"
	b += indent + "    charset utf-8;\n"
	b += indent + "}\n"
	return b
}
