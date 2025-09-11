package infrastructure

import "time"

type PostgresConnectionPoolStats struct {
	Acquired        int64         // Currently acquired (in-use) connections
	Idle            int64         // Currently idle (available) connections
	Total           int64         // Total connections in pool
	Max             int64         // Maximum connections allowed
	Min             int64         // Minimum connections allowed
	AcquireCount    int64         // Cumulative acquire count
	AcquireDuration time.Duration // Total time spent acquiring connections
	Constructing    int64         // Connections being constructed
}
