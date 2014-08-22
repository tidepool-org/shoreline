package models

type EmailTemplate interface {
	Format(tmplString string, details interface{}) (string, error)
}
