# Negative: safe URL construction -- must NOT trigger findings
scheme = "https://"
host = "example.com"
path = "/api/v1"
url = scheme + host + path
