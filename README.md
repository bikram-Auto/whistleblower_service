# Whistleblower Messaging Service (Prototype)

```
[Producer User]
        │  TCP (JSON)
        ▼
┌──────────────────┐
│    Consumer       │
│  (TCP + UDP out)  │
└──────────────────┘
        │  UDP
        ▼
┌──────────────────┐
│     Sender        │
│  (UDP in + TCP)   │
└──────────────────┘
        │  TCP (text lines)
        ▼
[Target User]
```

## Overview

This system provides fast, reliable, bidirectional messaging using:

- **TCP** for user connections  
- **UDP** for internal service-to-service relay  
- **Non-blocking sockets + epoll** for high concurrency  

## Flow

1. Producer user connects to **Consumer** via TCP  
2. Consumer forwards messages to **Sender** via UDP  
3. Sender delivers messages to the **Target User** via TCP  
4. Sender replies to Consumer over UDP  
5. Consumer responds to Producer via TCP  

## Running

### Start Sender:
```
./sender 7001 6001
```

### Start Consumer:
```
./consumer 7000 6001
```

## Testing

### Target User:
```
nc 127.0.0.1 7001
HELLO 5678
```

### Producer User:
```
nc 127.0.0.1 7000
HELLO 1234
{"senderId":"1234","toUserId":"5678","message":"hello","x_time":"now"}
```
