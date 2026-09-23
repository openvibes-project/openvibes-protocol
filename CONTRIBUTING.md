# Contributing

By submitting a contribution, you agree that it is licensed under the project's
[MIT License](LICENSE).

## AI-Assisted Contributions

AI coding tools may be used to prepare contributions, under these conditions:

1. **Disclose it.** A commit containing substantial AI-generated code or text
   carries a trailer naming the tool, for example
   `Co-Authored-By: Claude <noreply@anthropic.com>`. Alternatively, state in the
   pull request which parts were AI-assisted and with which tool.
2. **The human submitter is responsible.** You must understand, review, and test
   every line you submit. "The tool wrote it" is not a justification in review,
   and AI-assisted changes meet the same review bar as any other change.
3. **Contract changes are paired.** A change to anything that crosses the
   agent–platform boundary lands here first, updates [`PLAN.md`](PLAN.md) for
   both sides, and states whether it is compatible within schema version 1.
   Security-sensitive changes (authentication, enrollment, rule signing,
   ingestion) must specify their failure behaviour, not only the success path.
4. **Never share secrets with AI tools.** Do not paste credentials, private keys,
   enrollment tokens, or non-public endpoint data into prompts.
