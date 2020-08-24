package keycloak

func safePStr(s *string) (result string) {
	if s != nil {
		result = *s
	}
	return
}

func safePBool(s *bool) (result bool) {
	if s != nil {
		result = *s
	}
	return
}
