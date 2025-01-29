package v1

import "net/http"

func HealthRead() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("OK"))
		if err != nil {
			return
		}
	}
}
