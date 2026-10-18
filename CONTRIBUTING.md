# Contributing

Thanks for taking an interest. Small, focused changes are easiest to review.

## Getting started

You need Node.js 22 or later.

```sh
git clone https://github.com/AffixIO/affixio-agent-relay.git
cd affixio-agent-relay
npm ci
npm run lint
npm run typecheck
npm test        # unit tests, AffixIO mocked, no key needed
```

Live tests (`npm run test:live`) need an AffixIO API key and use real proofs. You do not need to run them for most changes.

## Making a change

1. Open an issue first for anything larger than a small fix, so we can agree the approach.
2. Keep pull requests to one change. Add or update unit tests for behaviour changes.
3. Make sure `npm run lint`, `npm run typecheck` and `npm test` all pass.
4. Update the README if you change the envelope format, the HTTP inbox, the MCP tools or a security property.

Look for issues labelled [good first issue](https://github.com/AffixIO/affixio-agent-relay/labels/good%20first%20issue) if you want somewhere to start.

## Security

Do not report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

Never commit `.env` files, `identity.json`, receipt logs or API keys.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0, the same licence as the project.
