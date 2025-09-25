package interceptor

func SplitMethod(fullMethod string) (service, method string) {
	// fullMethod: /package.service/method
	if len(fullMethod) == 0 || fullMethod[0] != '/' {
		return "", ""
	}
	fullMethod = fullMethod[1:]
	parts := make([]string, 2)

	for i, s := range []rune(fullMethod) {
		if s == '/' {
			parts[0] = string([]rune(fullMethod)[:i])
			parts[1] = string([]rune(fullMethod)[i+1:])
			return parts[0], parts[1]
		}
	}
	return fullMethod, ""
}
