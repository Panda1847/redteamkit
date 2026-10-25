# Contributing

Thank you for helping make RedTeamKit safer and more useful for authorized testing.

1. Open an issue describing the problem or proposal, without sensitive engagement details.
2. Keep changes focused and explain the threat-model or defensive value.
3. Add or update tests for behavior changes.
4. Run `python -m unittest -v` and `python -m compileall redteamkit` before opening a pull request.
5. Never add credentials, client identifiers, live targets, or real findings to the repository.

Pull requests should preserve the package's stdlib-only runtime and its safety defaults.
