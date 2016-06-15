As long as you've been building shoreline as part of using Tidepool's [runservers](https://github.com/tidepool-org/tools/blob/master/runservers) to run the entire platform locally, you should have the binary for this tool in a `dist/` directory at the root of this repository.

If you're not using runservers, please see the instructions in [the general README](../README.md) for how to build shoreline in isolation.

To use the `user-roles` binary, you must have the shoreline service running with config variables set in the environment. In other words, if you're using runservers, just run the following commands in the Terminal window/tab where you started the runservers (the commands will look more like e.g., `shoreline/dist/user-roles find --env local --role clinic` than what follows, where the full path has been omitted for concision).


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
