# IITK-COIN

### Steps for running the code

Go to `$GOPATH/src/` and then

```
git clone https://github.com/sparshs413/iitk-coin.git

cd iitk-coin
```

To run the app

```
go run main.go
```

The app currently features 3 endpoints
`/login`
`/signup` and
`/secretPage`.

The `/login` and `/signup` are public while the `/secretPage` is accessible only to the authorized users.

To test them, follow the following steps:

For, `/signup`

Go to Postman and in the Body Parameter, send a JSON in the following format

```
{
    "username":"demovalue",
    "name":"Demo Value",
    "rollno":190860
    "password":"demopassword"
}
```

PS: Roll Nos, only valid in range of [170001, 210000).

For, `/login`

Go to Postman and in the Body Parameter, send a JSON in the following format

```
{
    "rollno":190860
    "password":"demopassword"
}
```

On successful login, a JWT token will be output, on the Terminal.

For accessing `/secretPage`,
Use the previously generated token and send it in the form of a Header with `Key` as `Token` and with the previously generated JWT token.

If the token is valid, you will get a JSON with a "Secret Message".
