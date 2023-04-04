# A simple LAN / WAN

```mermaid

graph LR

subgraph LAN1 [LAN d3f:Network]
s1[server d3f:Server]
s2[server d3f:Server]
s3[server d3f:Server]
router-1[d3f:Router]
end


subgraph LAN2 [LAN d3f:Network ]
wifi-ap[d3f:WirelessAccessPoint d3f:WirelessRouter]
laptop1[d3f:LaptopComputer]
laptop2[d3f:LaptopComputer]
desktop1[d3f:DesktopComputer]
mobile[d3f:TabletComputer]
end

subgraph remote [d3f:Network d3f:PhysicalLocation]
vpn-terminator [d3f:EncryptedTunnels]
desktop-remote[d3f:DesktopComputer]
end

router-0 --- vpn-server[d3f:VPNServer VPN]
router-0 --- router-1
router-0 --- wifi-ap
router-0[d3f:Firewall d3f:Router ]

vpn-server --- vpn-terminator

```
