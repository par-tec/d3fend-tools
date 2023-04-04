# A server application

## Architecture

The following diagram shows the architecture of a server application,
running on a Linux server with RAM, storage, and an IP address.

The application process has a master process and various worker processes,
and relies on environment variables, configuration files, and log files.

```mermaid
graph LR


subgraph Server[d3f:Server Server Linux]
RAM[RAM d3f:VirtualMemorySpace]
DISK[Storage d3f:Volume]
ip-address[IP d3f:IPAddress]
end


subgraph application["application d3f:ApplicationProcess"]
master
worker
streams
env["env d3f:ProcessEnvironmentVariable"]
end


subgraph streams[Files and Sockets]
socket["socket d3f:Pipe"]
configuration["config d3f:ConfigurationFile"]
logs["logs d3f:LogFile"]
end

DISK -->|d3f:contains| logs
DISK -->|d3f:contains| configuration
RAM -->|d3f:contains| master-state
RAM -->|d3f:contains| worker-state
```

## Master process

The master process reads the configuration, manages connections and
binds to an IP address.

```mermaid
graph

subgraph master["master d3f:Subroutine d3f:Process"]
master-state[/"memory d3f:VirtualMemorySpace"/]
connection-manager
end

master --o|d3f:reads| configuration
master -->|d3f:uses| ip-address
master -->|d3f:uses| env
```

Moreover the connection manager assigns a worker thread for each connection,
eventually creating new threads and sockets as needed.

```mermaid
graph
connection-manager -->|"d3f:CreateSocket"| socket[/socket/]
connection-manager -->|"d3f:CreateThread"| worker
```


## Worker process

The worker process uses the configuration read by the master process,
and the sockets created by the connection manager.

The worker process authenticates the user, and then processes the data stream.

```mermaid
graph
subgraph worker[worker d3f:Subroutine d3f:Process]
authnz["authnz d3f:Authentication"]
worker-state[/"memory d3f:VirtualMemorySpace"/]
end
worker -->|d3f:uses| RAM
worker -->|d3f:uses| socket

user((d3f:User)) -->|d3f:connects| application
user -->|d3f:authenticates via| authnz
```
