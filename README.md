# SSH Relay Pro public update channel

This repository publishes verified distribution archives and a signed update index.
The private source repository is not mirrored. Application code already included in
distribution archives is part of the public download; source archives, development
profiles, identity files and credentials are not published.

A standard Linux GitHub-hosted runner checks private `release/X.Y.Z` branches every
five minutes using a read-only SSH deploy key. Scheduling may be delayed by GitHub.
The publisher checks all declared target packages before exposing a signed channel
entry. Failed runs are retried by the next scheduled run. Published version/hash
pairs are immutable. Historical versions below 6.0.10 are excluded because they
have not passed this channel's acceptance requirements.

Only `SOURCE_DEPLOY_KEY` and `CHANNEL_SIGNING_KEY` are stored as Actions secrets.
The workflow uses its own repository-scoped `GITHUB_TOKEN` to publish assets.
There is no private-repository Actions workflow, paid runner, external account,
or user-login requirement for downloading. Existing private Git LFS quota still
applies to reading source packages; no paid overage is enabled by this setup.

`channel.json` is an Ed25519-signed envelope containing the base64-encoded payload
and signature. The client pins the public key. Each package has a fixed version,
platform, size, SHA-256, source release commit and HTTPS download URL. Updating
this channel does not prove that an untested application build works correctly.

The index is refreshed daily, including when no release changes, to keep normal
repository activity. GitHub service outages, account restrictions and workflow
disabling are not bypassed or presented as guaranteed availability.
