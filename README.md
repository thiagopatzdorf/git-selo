# git selo

[![test](https://github.com/thiagopatzdorf/git-selo/actions/workflows/test.yml/badge.svg)](https://github.com/thiagopatzdorf/git-selo/actions/workflows/test.yml)

<!-- resumo: Arquivo privado dentro de um repositório Git comum: o .env vai cifrado (formato age) para as chaves SSH que o time já tem no GitHub, quem pode ler é código revisado em PR, e o check de CI reprova segredo em texto claro. -->

**Private files inside a normal Git repo.** Your `.env` is committed encrypted to your teammates'
GitHub SSH keys. People on the list see plaintext; everyone else (other collaborators, a leaked clone,
a forked CI) sees ciphertext. No server, no account, no new key to hand out.

```sh
npm i -g git-selo        # or: npm i -g github:thiagopatzdorf/git-selo  (zero dependencies, Node ≥ 20)
git selo init            # protects .env* by default
git selo add @alice @bob # fetches github.com/alice.keys and pins them in .selo.json
git add -A && git commit -m "the junior pushed the .env, and it's fine"
```

> "Source control being 100% or 0% access feels stupider than ever. I want private files in my repos.
> I want secret management that doesn't require some obscure 3rd party tools." — Theo, 2026

Git can't hide a blob from someone who clones the repo, so access really is all-or-nothing **at the
repo level**. `git selo` moves the boundary to the **file**: what's in the repo is public to the
repo's readers, but a protected file only opens for the keys listed for it.

## What it looks like (real output)

```console
$ git selo add @me @t3dotgg
@me: pinned 1 key(s)
@t3dotgg: pinned 21 key(s)
$ printf "STRIPE_KEY=sk_live_123\n" > .env
$ git add -A && git commit -qm "the junior pushed the .env"
$ git show HEAD:.env | head -3          # what GitHub (and everyone else) stores
age-encryption.org/v1
-> ssh-ed25519 hS6BXA XZU01pi5PLW63ektrcLNFJwljWjSl3HRll3eDOne2Ag
sotoQOmkrJB0kQz1CbDS2gvP2KUZi3mzy5YI6HqZBKk
$ cat .env                              # what a reader has on disk
STRIPE_KEY=sk_live_123
$ git selo status
.env
  readers: @me, @t3dotgg
  you can read
```

A teammate on the list clones and runs `git selo unlock` once; from then on `git pull`, `git diff`
and editing just work (diffs show plaintext). Someone not on the list gets the ciphertext on disk
and nothing breaks.

## Who can read what is code

`.selo.json` is the whole policy, reviewed in pull requests like anything else:

```json
{
  "groups": { "team": ["@alice", "@bob"], "billing": ["@alice"], "ci": ["age1q…"] },
  "files": {
    ".env*": ["team", "ci"],
    "contracts/**": ["billing"]
  },
  "keys": { "@alice": ["ssh-ed25519 AAAA…"], "@bob": ["ssh-rsa AAAA…"] }
}
```

- `files` uses `.gitattributes` patterns; the last match wins. `git selo` keeps a managed block in
  `.gitattributes` in sync.
- `@user` means "the SSH keys GitHub publishes for that user", **pinned** at `add` time. Encrypting
  never touches the network, and a key changed on GitHub can't silently change who reads: that
  only happens through a commit to `.selo.json`.
- `age1…` keys are for CI and for people without an ed25519/RSA key (`git selo key` makes one).

| command | does |
|---|---|
| `git selo init` | create `.selo.json` (protecting `.env*`), set up the Git filters in this clone |
| `git selo add @user … [--to group]` | pin their GitHub keys, add to the group, re-encrypt |
| `git selo remove @user [--from group]` | remove and re-encrypt (see Limits) |
| `git selo protect <pattern> [--for group]` | encrypt more files |
| `git selo status` | every protected file, its readers, and whether *you* can read it |
| `git selo check [--strict]` | CI gate (below) |
| `git selo unlock` / `lock` | decrypt this clone / put ciphertext back and remove the filters |
| `git selo cat <file> [--rev REV]` | print a protected file from any commit |
| `git selo key` | create `~/.config/selo/identity.txt` and print its `age1…` key |

## The CI gate

The one way to leak is a teammate **without** git selo adding a new `.env.local` in plaintext. The
check catches it, and also catches a file encrypted for a different set of people than
`.selo.json` says:

```yaml
# .github/workflows/secrets.yml
on: [pull_request, push]
jobs:
  selo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: thiagopatzdorf/git-selo@v0   # or: run: npx git-selo check --strict
```

```console
$ git selo check
git-selo: FAIL: .env.local is committed in PLAINTEXT
git-selo: warning: server.pem looks like a secret but is not protected (git selo protect server.pem)
```

For CI that needs the secrets: `git selo key` on any machine, `git selo add age1… --to ci`, and put
the secret line in a CI secret as `SELO_IDENTITY`.

## Not a new crypto format

Files are standard [age](https://age-encryption.org) v1. If `git selo` disappeared tomorrow:

```sh
git show HEAD:.env | age -d -i ~/.ssh/id_ed25519
```

The test suite checks this both ways against the official `age` binary (X25519, ssh-ed25519,
ssh-rsa; empty, 1 byte, exactly 64 KiB, 64 KiB + 1, 200 KB).

Keys are read from `$SELO_IDENTITY`, `$SELO_IDENTITY_FILE`, `~/.config/selo/identity.txt`,
`~/.ssh/id_ed25519` and `~/.ssh/id_rsa`.

## Tested against real accounts

From the GitHub key endpoints, copied into `test/fixtures` on 2026-11-20:

- **@t3dotgg**: 21 keys (1 RSA-4096, 20 ed25519) → 21 recipients; the official `age` parses the
  result and only says "no identity matched".
- **@FiloSottile** (the author of age!) publishes only an ECDSA key, which age doesn't support:
  `git selo add` stops and points to `git selo key` instead of failing silently.

## Limits, said plainly

- **Removing someone doesn't un-share the past.** They keep what they already pulled, and old
  commits stay encrypted to their key. `remove` re-encrypts going forward; **rotate the actual
  secrets** (new API key, new password).
- **Passphrase-protected SSH keys** can't be used: the Git filter has no terminal to ask. Use
  `git selo key` for a dedicated key (the tool says so when it skips one).
- **Branch-level privacy** isn't solved by this. A whole private branch needs a separate remote
  (or encrypting every file in it).
- File *names*, sizes and commit times stay visible. Only contents are protected.
- One process per protected file on add/checkout: fine for dozens of secret files, not for
  thousands.

## How it works

A Git clean/smudge filter (`.gitattributes` → `filter=selo`). `clean` encrypts on `git add`;
`smudge` decrypts on checkout when you hold a key and otherwise leaves the ciphertext. age
encryption is randomized, so the last ciphertext is cached in `.git/selo/` per file and reused
while the plaintext and the reader list are unchanged. Without that cache, `git status` would show
every protected file as modified.

---

## Em português

`git selo` põe arquivo privado dentro de um repositório Git comum. O `.env` vai cifrado para as
chaves SSH que cada pessoa do time já tem no GitHub: quem está na lista lê, o resto vê só o cifrado.
Quem pode ler é código (`.selo.json`), revisado em PR. O formato é o age, aberto, e abre com a
ferramenta oficial mesmo sem o git selo. Licença MIT.
