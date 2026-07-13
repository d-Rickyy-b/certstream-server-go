package config

type BufferSizes struct {
	Websocket        int `mapstructure:"websocket"`
	CTLog            int `mapstructure:"ctlog"`
	BroadcastManager int `mapstructure:"broadcastmanager"`
	Dispatcher       int `mapstructure:"dispatcher"`
}

func (b *BufferSizes) Valid() bool {
	if b.Websocket <= 0 || b.CTLog <= 0 || b.BroadcastManager <= 0 || b.Dispatcher <= 0 {
		return false
	}

	return true
}
