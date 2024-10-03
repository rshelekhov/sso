package settings

type AppStorageType string

const (
	AppStorageTypeDefault  = "default"
	AppStorageTypeMongo    = "mongo"
	AppStorageTypePostgres = "postgres"
)

// TODO: add env variable to .env file
type AppStorage struct {
	Type     AppStorageType `mapstructure:"APP_STORAGE_TYPE" endDefault:"default"`
	Mongo    *MongoStorageParams
	Postgres *PostgresStorageParams
}
