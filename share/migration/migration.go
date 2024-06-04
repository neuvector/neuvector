package migration

const (
	TARGET_SECRET_SOURCE_NAME_CACERT = "target-cacert"
	TARGET_SECRET_SOURCE_NAME_CERT   = "target-cert"
	TARGET_SECRET_SOURCE_NAME_KEY    = "target-key"

	CACERT_FILENAME = "ca.crt"
	CERT_FILENAME   = "tls.crt"
	KEY_FILENAME    = "tls.key"

	NEW_SECRET_PREFIX    = "new-"
	DEST_SECRET_PREFIX   = "dest-"
	ACTIVE_SECRET_PREFIX = ""
)
