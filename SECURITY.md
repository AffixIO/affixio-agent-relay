# Security policy

## Reporting a vulnerability

Please report security issues privately by email to hello@affix-io.com with "agent-relay security" in the subject, or through the contact details at https://www.affix-io.com/security/. Do not open a public issue for a suspected vulnerability.

Include the affected version or commit, steps to reproduce, and the impact you expect. We aim to acknowledge reports within five working days.

## Scope

In scope: the code in this repository, including envelope, grant and approval verification, replay protection, the HTTP inbox, the MCP server and the receipt log.

Out of scope here: the AffixIO API and services themselves. Report those through https://www.affix-io.com/security/.

## Supported versions

Only the latest release on the `main` branch receives fixes while the project is below 1.0.

## Handling secrets

Never commit `.env` files, `identity.json` or AffixIO API keys. The repository's `.gitignore` excludes them, and `agent-relay init` writes a `.gitignore` into each state folder.
