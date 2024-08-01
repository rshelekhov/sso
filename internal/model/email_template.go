package model

type EmailTemplateType string

const (
	EmailTemplateTypeVerifyEmail EmailTemplateType = "verify-email"

	DefaultTemplateExtension = "html"
)

func (t EmailTemplateType) String() string {
	return string(t)
}

func (t EmailTemplateType) FileName() string {
	return string(t) + "." + DefaultTemplateExtension
}
