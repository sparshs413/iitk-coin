# IITK Coin

## SnT Project 2021, Programming Club

This repository contains the code for the IITKCoin, a vision of a pseudo-currency for use in the IITK Campus.

### Relevant Links

-   [Midterm Evaluation presentation](https://docs.google.com/presentation/d/1kriN-7A3v1RlXUDL5NETX3roJKRMJInptkWofIxY8dg/edit?usp=sharing)
-   [Midterm Documentation](https://docs.google.com/document/d/1bvOWH4k0U-l2pQ1jLWIDzOkJ2wbHNW4jJw7tMWkUV6o/edit?usp=sharing)

## Table Of Content

-   [Development Environment](#development-environment)
-   [Directory Structure](#directory-structure)
-   [Usage](#usage)
-   [Endpoints](#endpoints)

## Development Environment

```bash
- OS:           Ubuntu 20.04.2 LTS x86-64    # https://ubuntu.com/download
- Kernel:       Linux 5.4.0-80-generic       # https://kernel.ubuntu.com/
- go version:   go1.16.6 linux/amd64         # https://golang.org/dl/
- text editor:  VSCode    	                  # https://code.visualstudio.com/download
- terminal:     Zsh                          # https://ohmyz.sh/

```

## Directory Structure

```
.

├── auth
│   └── auth.go
├── controllers
│   └── controller.go
├── database
│   └── database.go
├── db
    ├── transactionHistory.db
│   └── users.db
├── go.mod
├── go.sum
├── main.go
├── models
│   └── models.go
├── README.md

5 directories, 10 files
```

## Usage

### Use this repo

```bash
cd $GOPATH/src/github.com/<username>
git clone https://github.com/gurbaaz27/iitk-coin.git
cd repo
go run main.go
#, or build the program and run the executable
go build
./iitk-coin
```

Output should look like

```
2021/07/26 22:24:25 User Database opened and table created (if not existed) successfully!
2021/07/26 22:24:25 Wallet Database opened and table created (if not existed) successfully!
2021/07/26 22:24:25 Transaction Database opened and table created (if not existed) successfully!
2021/07/26 22:24:25 Starting server, Listening on http://localhost:8080
```

### Use Docker Image

```
docker run --rm -p 8080:8080 sparshs413/iitk-coin
```

## Endpoints

POST requests take place via `JSON` requests. A typical usage would look like

```bash
curl -d '<json-request>' -H 'Content-Type: application/json' http://localhost:8080/<endpoint>
```

-   `/signup` : `POST`

```json
{ "username": "<username>", "name": "<name>", "rollno": "<rollno>", "password": "<password>" }
```

PS: Roll Nos, only valid in range of [170001, 210000).

-   `/login` : `POST`

```json
{ "rollno": "<rollno>", "password": "<password>" }
```

-   `/balance` : `POST`

```json
{ "rollno": "<rollno>" }
```

-   `/giveCoins` : `POST`

```json
{ "rollno": "<rollno>", "coins": "<coins>" }
```

-   `/transferCoins` : `POST`

```json
{ "senderRollno": "<senderRollno>", "receiverRollno": "<receiverRollno>", "transferCoins": "<transferCoins>" }
```

GET requests:

-   `/secretpage` : `GET`

```bash
curl http://localhost:8080/secretPage
```
