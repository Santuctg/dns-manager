# Publishing DNS Manager v0.6.11

This repository is currently only partially populated. **Do not deploy from the repository until the complete project tree has been pushed and verified.**

The complete cumulative source/docs ZIP is named `dns-manager-0.6.11-documented.zip` in the ChatGPT delivery. Use the accompanying `publish-dns-manager-v0.6.11.sh` helper from a trusted machine with `gh` authenticated, `git`, `unzip`, `rsync` and `sha256sum`.

```bash
gh auth login
bash publish-dns-manager-v0.6.11.sh dns-manager-0.6.11-documented.zip
```

The helper extracts the ZIP, checks the version and screens for common secret/data files, clones `Santuctg/dns-manager`, commits source and docs, pushes to `main` (no force), and creates the GitHub Release `v0.6.11` with the ZIP attached.

Before publication, review source for confidential domains, passwords, private addresses, tokens, credentials and cryptographic material. Only publish to a public repository if source disclosure is intended.

When publication completes, verify the default branch includes `app/`, `privileged/`, `packaging/`, `tests/`, the `VERSION` file and the release asset, and that the release tag resolves to the same source commit.
