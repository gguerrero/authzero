## Build and Run
To build the project:

```bash
$ go build server.go
```

To run the server:
```bash
$ ./server
2019/12/16 15:11:18 Booting Server on localhost:8000...
2019/12/16 15:11:25 GET /api/private 200[OK]
2019/12/16 15:11:26 GET /api/public 200[OK]
...
```

Server responses:
**/api/public**
```json
{
    "message": "Hello from a public endpoint! You don't need to be authenticated to see this.",
    "statusCode": 200
}
```

**/api/private**
```json
{
    "message": "Hello from a private endpoint! You need to be authenticated to see this."
}
```
