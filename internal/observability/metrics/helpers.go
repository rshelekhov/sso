package metrics

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws/awserr"
)

func extractDBErrorType(err error) string {
	if err == nil {
		return "none"
	}

	errStr := strings.ToLower(err.Error())

	switch {
	// Connection errors
	case strings.Contains(errStr, "connection refused"), strings.Contains(errStr, "connection reset"):
		return "connection_refused"
	case strings.Contains(errStr, "timeout"), strings.Contains(errStr, "deadline exceeded"):
		return "timeout"
	case strings.Contains(errStr, "connection"):
		return "connection_error"

	// PostgreSQL specific
	case strings.Contains(errStr, "duplicate key"), strings.Contains(errStr, "unique constraint"):
		return "duplicate_key"
	case strings.Contains(errStr, "foreign key constraint"):
		return "foreign_key_violation"
	case strings.Contains(errStr, "not null constraint"):
		return "not_null_violation"
	case strings.Contains(errStr, "no rows"):
		return "no_rows_found"

	// MongoDB specific
	case strings.Contains(errStr, "duplicate key error"):
		return "duplicate_key"
	case strings.Contains(errStr, "no documents"):
		return "no_documents_found"
	case strings.Contains(errStr, "write conflict"):
		return "write_conflict"

	// Generic database errors
	case strings.Contains(errStr, "syntax error"):
		return "syntax_error"
	case strings.Contains(errStr, "permission denied"):
		return "permission_denied"
	case strings.Contains(errStr, "database"):
		return "database_error"

	default:
		return "unknown"
	}
}

func extractS3ErrorCode(err error) string {
	if err == nil {
		return "none"
	}

	if awsErr, ok := err.(awserr.Error); ok {
		return awsErr.Code()
	}

	// Fallback to generic error classification
	errStr := strings.ToLower(err.Error())

	switch {
	case strings.Contains(errStr, "nosuchkey"):
		return "NoSuchKey"
	case strings.Contains(errStr, "accessdenied"):
		return "AccessDenied"
	case strings.Contains(errStr, "timeout"):
		return "Timeout"
	case strings.Contains(errStr, "connection"):
		return "ConnectionError"
	default:
		return "Unknown"
	}
}

func extractRedisErrorType(err error) string {
	if err == nil {
		return "none"
	}

	errStr := strings.ToLower(err.Error())

	switch {
	// Connection errors
	case strings.Contains(errStr, "connection refused"), strings.Contains(errStr, "connection reset"):
		return "connection_refused"
	case strings.Contains(errStr, "timeout"), strings.Contains(errStr, "deadline exceeded"):
		return "timeout"
	case strings.Contains(errStr, "connection closed"), strings.Contains(errStr, "broken pipe"):
		return "connection_closed"
	case strings.Contains(errStr, "connection"):
		return "connection_error"

	// Redis specific protocol errors
	case strings.Contains(errStr, "wrongtype"):
		return "wrong_type"
	case strings.Contains(errStr, "noauth"):
		return "auth_required"
	case strings.Contains(errStr, "noperm"):
		return "permission_denied"
	case strings.Contains(errStr, "readonly"):
		return "readonly_error"

	// Redis cluster/replication errors
	case strings.Contains(errStr, "clusterdown"):
		return "cluster_down"
	case strings.Contains(errStr, "moved"), strings.Contains(errStr, "ask"):
		return "cluster_redirect"
	case strings.Contains(errStr, "loading"):
		return "loading_dataset"

	// Pool/resource errors
	case strings.Contains(errStr, "pool exhausted"), strings.Contains(errStr, "pool timeout"):
		return "pool_exhausted"
	case strings.Contains(errStr, "too many connections"):
		return "max_connections"

	// Generic Redis errors
	case strings.Contains(errStr, "redis"):
		return "redis_error"

	default:
		return "unknown"
	}
}
