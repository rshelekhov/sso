package settings

import (
	"time"
)

type StorageType string

const (
	StorageTypeMongo    StorageType = "mongo"
	StorageTypePostgres StorageType = "postgres"
)

type Storage struct {
	Type     StorageType     `yaml:"Type"`
	Mongo    *MongoParams    `yaml:"Mongo"`
	Postgres *PostgresParams `yaml:"Postgres"`
}

type MongoParams struct {
	URI     string        `yaml:"URI"`
	DBName  string        `yaml:"DBName"`
	Timeout time.Duration `yaml:"Timeout" default:"30s"`
}

type PostgresParams struct {
	ConnURL      string        `yaml:"ConnURL"`
	ConnPoolSize int           `yaml:"ConnPoolSize" default:"10"`
	ReadTimeout  time.Duration `yaml:"ReadTimeout" default:"5s"`
	WriteTimeout time.Duration `yaml:"WriteTimeout" default:"5s"`
	IdleTimeout  time.Duration `yaml:"IdleTimeout" default:"60s"`
	DialTimeout  time.Duration `yaml:"DialTimeout" default:"10s"`
}
