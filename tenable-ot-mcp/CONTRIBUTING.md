# Contributing

Thanks for your interest in this project. A few notes that will save us
both time.

## Before opening an issue or merge request

- **Search existing issues first.** Same bug, same idea, same question.
- **Be specific.** Version (image tag), Tenable OT API version, exact tool
  call, exact error. "Doesn't work" alone is hard to act on.

## Bug reports

Use the **Bug** issue template. Reproducible test cases get fixed
fastest.

## Feature requests

Open an issue with the prefix `[idea]`. We'll discuss before any code
gets written. The project intentionally has a narrow scope (MCP server
for Tenable OT data); features outside that scope will likely be declined.

## Pull requests

- Open an issue first if the change is non-trivial. Saves you from
  writing code we won't merge.
- One change per MR. Easier to review, easier to revert.
- Add tests for new behavior. The CI pipeline runs them on every push.
- Update the README and tool catalog if you add or change tools.
- Sign off your commits (`git commit -s`) — we use the
  [Developer Certificate of Origin](https://developercertificate.org/).
- Follow the existing code style. `ruff format` for Python, no
  configuration overrides.

## Coding standards

- Python 3.12+, async-first.
- Type hints on all public functions and tool implementations.
- No silent failures. Tools should raise informative errors that the
  consuming AI can surface to the user.
- Tools must NOT precompute analyses. They expose joined data; the
  consuming AI does the analysis. (This is a project-wide
  architectural rule; see README.)
- Stateless: no caching of Tenable OT data inside the server process beyond
  the lifetime of a single MCP request.

## Releases & versioning

We follow [Semantic Versioning](https://semver.org/):

- `MAJOR` — breaking API changes (tool removals, schema breaks).
- `MINOR` — new tools, additive changes.
- `PATCH` — bug fixes only.

Releases are tagged in git and trigger a CI/CD pipeline that publishes
a multi-arch image to the GitLab Container Registry.

## License

By contributing, you agree your contributions are licensed under
Apache 2.0 (the project's license).
