package config

import (
	"flag"
	"log"
	"os"

	"github.com/spf13/viper"
)

const CONFIG_PATH = "CONFIG_PATH"

func MustLoad() *ServerSettings {
	configPath := fetchConfigPath()

	if configPath == "" {
		panic("config path is empty")
	}

	return MustLoadPath(configPath)
}

func MustLoadPath(configPath string) *ServerSettings {
	cfg := ServerSettings{}

	viper.SetConfigFile(configPath)

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("error finding or reading config file: %s", err)
	}

	viper.AutomaticEnv()

	err = viper.Unmarshal(&cfg)
	if err != nil {
		log.Fatalf("error unmarshalling config file into struct: %s: ", err)
	}

	return &cfg
}

// fetchConfigPath fetches config path from command line flag or environment variable.
// Priority: flag > env > default.
// Default value is empty string.
func fetchConfigPath() string {
	var v string

	flag.StringVar(&v, "config", "", "path to config file")
	flag.Parse()

	if v == "" {
		v = os.Getenv(CONFIG_PATH)
	}

	return v
}
