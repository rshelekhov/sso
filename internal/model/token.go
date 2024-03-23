package model

type RefreshRequestData struct {
	RefreshToken string
	AppID        int
	UserDevice   UserDeviceRequestData
}
