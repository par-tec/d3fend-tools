# D3fend Tools

D3FEND is a MITRE knowledge base for cybersecurity that categorizes digital artifacts,
offensive and defensive techniques.

This repository contains tools to help you use the D3FEND knowledge base
to classify your digital platforms described in terms of various Description Languages/Infrastructure as Code (IaC) tools,
such as Kubernetes manifest files and Mermaid JS.

## Contributing

Please, see [CONTRIBUTING.md](CONTRIBUTING.md) for more details on:

- using [pre-commit](CONTRIBUTING.md#pre-commit);
- following the git flow and making good [pull requests](CONTRIBUTING.md#making-a-pr).

## Using this repository

You can create new projects starting from this repository,
so you can use a consistent CI and checks for different projects.

Besides all the explanations in the [CONTRIBUTING.md](CONTRIBUTING.md) file, you can use the docker-compose file
(e.g. if you prefer to use docker instead of installing the tools locally)

```bash
docker-compose run pre-commit
```
