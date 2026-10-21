We need to redesign that, cause it should support multiple hubs. How i see that:

# hub-server
hub-server should know it's local hub-net network. 
It should expose api `hub/net/share` that generates a temporary code. This code should contain temporary authorization for `hub-net` and `hub-net-node` and address of a node. Default node address is hub.v57.dev/node, it can be excluded from the link to reduce it's size. Link can be converted to base64url.

## Hub name
hub-server should have a name. 
New api:
`hub/header` streams hub name
`hub/header/set` updates hub name
```ts
interface HubHeader { 
  name: string // defaults to hostname
}
```
We are using header instead of name to expand this functionality later

# hub-net
## Multiple hubs
hub-net should have multiple `Service` classes and start with no connection, dynamically updating them using commands.
Each hub can use a different node, so there should be a separate node connection list

## Join hub network with a temporary code
Add command `hub-net join $code`
It
1. Authorizes with hub's `hub-net` using this code
2. Connects to `hub-server` through `hub-net` virtual address
3. Authorizes with this code
4. Reads `hub/header` (just a single value and stop the stream, updates on restart)

It should output:
```
Joined $hubname
Host: $virtual-host
IP: $virtual-ip
```

Leave hub using `hub-net leave $hubname`
List of connected hubs using `hub-net list`
Open port using `hub-net open $port $hubname`
Remove all data using `hub-net removeAll` (useful for tests)

# Hub App
Add `Share Network` toggle to `HubNetworkView`. It will install VPN profile if needed and activate it
Add `Invite Code` button that calls `hub/net/share` api and copies it to the clipboard
Add Join with Code button to `Home`. A single textfield and join button. Uses `hub/net/share` code to join hub network

Add ability to route all network traffic through any `hub-net` / `Hub App` in the hub network
