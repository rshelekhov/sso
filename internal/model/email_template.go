package model

type EmailTemplateType string

const (
	EmailTemplateTypeVerifyEmail   EmailTemplateType = "verify-email"
	EmailTemplateTypeResetPassword EmailTemplateType = "reset-password"

	DefaultTemplateExtension = "html"
)

func (t EmailTemplateType) String() string {
	return string(t)
}

func (t EmailTemplateType) FileName() string {
	return string(t) + "." + DefaultTemplateExtension
}

func (t EmailTemplateType) Subject() string {
	switch t {
	case EmailTemplateTypeVerifyEmail:
		return "Verify your email address"
	case EmailTemplateTypeResetPassword:
		return "Reset password instructions"
	default:
		return ""
	}
}
