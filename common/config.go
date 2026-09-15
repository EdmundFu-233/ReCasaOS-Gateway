package common

import (
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/IceWhaleTech/CasaOS-Common/utils/constants"
)

const (
	ConfigKeyLogPath     = "gateway.LogPath"
	ConfigKeyLogSaveName = "gateway.LogSaveName"
	ConfigKeyLogFileExt  = "gateway.LogFileExt"
	ConfigKeyGatewayPort = "gateway.Port"
	ConfigKeyRuntimePath = "common.RuntimePath"
	// ConfigKeyTrustedProxyCIDRs lists the CIDRs whose X-Forwarded-For and
	// X-Real-IP headers the gateway believes. Any other peer's forwarding
	// headers are ignored and the peer address is used as the client IP.
	ConfigKeyTrustedProxyCIDRs = "gateway.TrustedProxyCIDRs"
	// ConfigKeyRouteTargetCIDRs lists the CIDRs a registered route target
	// may resolve to. Loopback is always allowed; anything else must be
	// listed here. DNS names other than localhost are rejected outright so
	// admission never depends on resolution.
	ConfigKeyRouteTargetCIDRs = "gateway.RouteTargetCIDRs"
	// ConfigKeyRouteLeaseTTL bounds how long a registered route stays
	// valid without renewal, for example "24h". Range: 1m to 720h.
	ConfigKeyRouteLeaseTTL = "gateway.RouteLeaseTTL"
	// ConfigKeyCORSOrigins is a comma-separated list of exact origins
	// allowed to use browser credentials against the management API.
	// Empty (the default) means same-origin only: no CORS headers are
	// emitted and no preflight is answered.
	ConfigKeyCORSOrigins = "gateway.CORSOrigins"

	GatewayName       = "gateway"
	GatewayConfigType = "ini"
)

func LoadConfig() (*viper.Viper, error) {
	config := viper.New()

	config.SetDefault(ConfigKeyLogPath, constants.DefaultLogPath)
	config.SetDefault(ConfigKeyLogSaveName, GatewayName)
	config.SetDefault(ConfigKeyLogFileExt, "log")

	config.SetDefault(ConfigKeyRuntimePath, constants.DefaultRuntimePath) // See https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch05s13.html
	config.SetDefault(ConfigKeyTrustedProxyCIDRs, "127.0.0.1/32,::1/128")
	config.SetDefault(ConfigKeyRouteTargetCIDRs, "127.0.0.1/32,::1/128")
	config.SetDefault(ConfigKeyRouteLeaseTTL, "24h")
	config.SetDefault(ConfigKeyCORSOrigins, "")

	config.SetConfigName(GatewayName)
	config.SetConfigType(GatewayConfigType)

	if currentDirectory, err := os.Getwd(); err != nil {
		log.Println(err)
	} else {
		config.AddConfigPath(currentDirectory)
		config.AddConfigPath(filepath.Join(currentDirectory, "conf"))
	}

	if configPath, success := os.LookupEnv("CASAOS_CONFIG_PATH"); success {
		config.AddConfigPath(configPath)
	}

	config.AddConfigPath(constants.DefaultConfigPath)

	if err := config.ReadInConfig(); err != nil {
		return nil, err
	}

	return config, nil
}
