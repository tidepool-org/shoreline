## Add role to a user

```
$ user-roles add --env local --email foo@bar.org --role clinic
```

## Remove role from a user

```
$ user-roles remove --env local --email foo@bar.org --role clinic
```

## Find users by role

```
$ user-roles find --env local --role clinic
```

### Roles

The `role` parameter can be one of:

`clinic`

### Environments

The `env` parameter can be one of:

`prd`
`stg`
`dev`
`local`
