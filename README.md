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

The app currently features 6 endpoints
`/login`,
`/signup`,
`/secretPage`,
`/giveCoins`,
`/transferCoins` and
`/balance`.

The `/login`, `/signup`, `/giveCoins`, `/transferCoins` and `/balance` are public while the `/secretPage` is accessible only to the authorized users.

To test them, follow the following steps:

For, `/signup`

Go to Postman and in the Body Parameter, send a JSON in the following format

```
{
    "username":"demovalue",      // User's Username
    "name":"Demo Value",         // User's Name
    "rollno":190860              // User's Rollno
    "password":"demopassword"    // User's Password
}
```

PS: Roll Nos, only valid in range of [170001, 210000).

For, `/login`

Go to Postman and in the Body Parameter, send a JSON in the following format

```
{
    "rollno":190860              // User's Rollno
    "password":"demopassword"    // User's Password
}
```

On successful login, a JWT token will be printed, on the Terminal.

For accessing `/secretPage`,
Use the previously generated token and send it in the form of a Header with `Key` as `Token` and with the previously generated JWT token.

If the token is valid, you will get a JSON with a "Secret Message".

For, `/balance`,
this endpoint is used to get the balance of a particular user.

Go to Postman and in the Body Parameter, send a JSON in the following format

```
{
    "rollno": 190860     // User's Rollno
}
```

If the user is present, we get the number of Coins held by the user.

For, `/giveCoins`,
this endpoint is used to give coins to a particular user.

Go to Postman and in the Body Parameter, send a JSON in the following format

```
{
    "rollno": 190860,  // User's Rollno
    "coins":10         // Amount of Coins to be given to user
}
```

If the user is present, the coins for the user gets updated.

For, `/transferCoins`,
this endpoint is used to transfer coins between users.

Go to Postman and in the Body Parameter, send a JSON in the following format

```
{
    "senderRollno": 190861,      // Sender's Rollno
    "receiverRollno": 190860,    // Receiver's Rollno
    "transferCoins": 23          // # coins to be transferred
}
```

On successful transaction, the coins gets transferred.

#### For concurrency used `Mutex` in order to avoid conflicts and the steps run sequentially.
