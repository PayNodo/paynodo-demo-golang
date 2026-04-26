# PayNodo Brazil V2 Go Demo

Backend-only Go demo for PayNodo Brazil V2.

## Requirements

- Go 1.22+

No external Go modules are required.

## Setup

```shell
cp .env.example .env
```

Edit `.env` and replace sandbox values with the credentials from the merchant cabinet.
Save the merchant private key as `merchant-private-key.pem`, or set `PAYNODO_PRIVATE_KEY_PEM` directly in `.env`.

## Generate a signed PayIn preview

```shell
go run ./cmd/demo sign-payin
```

## Send sandbox requests

```shell
go run ./cmd/demo payin
go run ./cmd/demo payout
go run ./cmd/demo status
go run ./cmd/demo balance
go run ./cmd/demo methods
```

## Verify a callback signature

```shell
PAYNODO_CALLBACK_BODY='{"orderNo":"ORDPI2026000001","status":"SUCCESS"}' \
PAYNODO_CALLBACK_TIMESTAMP='2026-04-17T13:25:10.000Z' \
PAYNODO_CALLBACK_SIGNATURE='replace_with_callback_signature' \
go run ./cmd/demo verify-callback
```

The private key and merchant secret must stay on the merchant backend.
