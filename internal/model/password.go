package model

type (
	ResetPasswordRequestData struct {
		Email string
		AppID string
	}

	ChangePasswordRequestData struct {
		ResetPasswordToken string
		UpdatedPassword    string
		AppID              string
	}
)
