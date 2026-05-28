package authentication

func Pointer[T comparable](v T) *T {
	return &v
}
