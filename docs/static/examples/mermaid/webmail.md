# A simple webmail architecture

```mermaid
graph LR

%% 1. Design here your architecture using MermaidJS syntax.
%% 2. Click on the "D3FEND" tab to see the possible attack paths.
%% 3. Explore the other features selecting the other tabs!

%% The simple arrow maps to d3f:accesses
Client[Client d3f:InternetNetworkTraffic d3f:Browser] --> |d3f:WebResourceAccess| WebMail

%% Improve the diagram using font-awesome icons.
WebMail -->|d3f:Email| MTA[Mail Server fa:fa-envelope fa:fa-folder]

%% Associated d3f:DigitalArtifacts can be referenced via URIs too.
Authorization[d3f:AuthorizationService fa:fa-user-secret] --> |d3f:authenticates| Client
MTA --o Authorization

%% Discover digital artifacts using the completion feature.
%%   Type "d3f:" and press CTRL+space to see the list of available artifacts.
%%   Then use TAB to complete.
```

## More details on the Mail Architecture

```mermaid

graph

subgraph MTA
AVAS -->|fa:fa-envelope| SMTP
IMAP --> Mailstore[Mailstore fa:fa-envelope fa:fa-folder]
end
```

## Webmail Architecture

```mermaid
graph

%% The webapp has a database for user settings.
be --> |d3f:DatabaseQuery| mysql

%% Font-awesome icons can be used to indicate that
%%   a node is a class (e.g. fa-react maps to a WebUI)
subgraph WebMail[WebMail fab:fa-react fa:fa-envelope]
    fe[fab:fa-react frontend app d3f:ContainerProcess]
    be[backend API fab:fa-python d3f:WebServerApplication d3f:ContainerProcess]
    waf[fa:fa-filter d3f:WebApplicationFirewall]
    waf --> fe
    waf --> be
end

subgraph mysql
    db[(User preferences DB fa:fa-user)]
    db --> db-datastore[(datastore fa:fa-hard-drive)]
    %% Protect mysql from disk content wipe
    db --> db-backup[(mysql backup datastore fa:fa-hard-drive)]

end

```

## Containerized Webmail Architecture

```mermaid

graph

%% Containerized application
subgraph Platform
MTA
WebMail
mysql
Authorization
end

```
