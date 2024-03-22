package requestid

type Option interface {
	apply(*options)
}

type optionApplyer func(*options)

func (a optionApplyer) apply(opt *options) {
	a(opt)
}

type options struct {
	chainRequestID bool
	validator      requestIDValidator
}

type requestIDValidator func(string) bool

func defaultRequestIDValidator(requestID string) bool {
	return true
}
