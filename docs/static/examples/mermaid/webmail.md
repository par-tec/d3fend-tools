# A simple webmail architecture

```mermaid
graph LR

%% 1. Design here your architecture using MermaidJS syntax.
%% 2. Click on the "D3FEND" tab to see the possible attack paths.
%% 3. Explore the other features selecting the other tabs!

%% The simple arrow maps to d3f:accesses
Client[Client d3f:InternetNetworkTraffic d3f:Browser] --> |d3f:WebResourceAccess| WebMail

%% Improve the diagram using font-awesome icons.
WebMail -->|d3f:Email| MTA[Mail Server d3f:MessageTransferAgent]

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
AVAS -->|d3f:Email| SMTP
IMAP --> Mailstore[Mailstore d3f:Email d3f:Volume]
end
```

## Webmail Architecture

```mermaid
graph

%% The webapp has a database for user settings.
be --> |d3f:DatabaseQuery| mysql

%% Font-awesome icons can be used to indicate that
%%   a node is a class (e.g. fa-react maps to a WebUI)
subgraph WebMail[WebMail fab:fa-react d3f:Email]
    fe[fab:fa-react frontend app d3f:ContainerProcess]
    be[backend API fab:fa-python d3f:WebServerApplication d3f:ContainerProcess]
    waf[WAF fa:fa-filter d3f:WebApplicationFirewall]
    waf -->|d3f:WebResourceAccess| fe
    waf -->|d3f:WebResourceAccess| be
end

subgraph mysql[mysql d3f:Database]
    db[(User preferences DB d3f:UserAccount)]
    db --> db-datastore[(datastore d3f:Volume)]
    %% Protect mysql from disk content wipe
    db --> db-backup[(mysql backup datastore d3f:Database d3f:Volume)]

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
