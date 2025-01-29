package entity

type (
	ResetPasswordRequestData struct {
		Email string
	}

	ChangePasswordRequestData struct {
		ResetPasswordToken string
		UpdatedPassword    string
	}

	ChangingPasswordResult struct {
		TokenExpired bool
	}
)
