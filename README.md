

                       (UDP — ultra-fast internal messages)
   ┌─────────────┐                                   ┌──────────────┐
   │   Sender     │  <------------UDP------------->  │   Consumer   │
   │ (C Program)  │                                  │ (C Program)  │
   └──────┬──────┘                                   └──────┬───────┘
          |                                                 ^
          | TCP (reliable)                                  │
          v                                                 │
   ┌──────────────────┐                             ┌──────────────────┐
   │ Business Service  │                            │ Business Service │
   │ (NestJS / C / Go) │                            │ (NestJS / C / Go)│
   └──────────────────┘                             └──────────────────┘





1. UDP CHANNEL → ONLY for Sender ↔ Consumer
	- Fastest possible transport
	- No handshake
	- Very low bandwidth
	- Best for internal "relay" messages
	- No need for reliability (your business service handles that through TCP)



Sender sends:
	`sender_id:receiver_id:message:hmac`

Consumer replies:
	`sender_id:message:new_hmac`



* Both use:
	Non-blocking UDP sockets
	epoll() for 10k+ clients
	HMAC for security
	.env secret key







