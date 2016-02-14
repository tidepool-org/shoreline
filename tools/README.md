
## Add role to an account

```
$ go run accounts_cli.go add --email foo@bar.org --role clinic --env local
```

## Remove role from account

```
$ go run accounts_cli.go remove --email foo@bar.org --role clinic --env local
```

## Find accounts by role

```
$ go run accounts_cli.go find --role clinic --env local
```

### Target Environments

`local`
`dev`
`stg`
`prd`

