package model

type RefreshRequestData struct {
	RefreshToken string
	AppID        int32
	UserDevice   UserDeviceRequestData
}
