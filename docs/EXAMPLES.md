# Usage examples

Use mop with command-line tools that accept credentials through environment
variables, stdin, files, or file descriptors. These examples use Bash or zsh.

Install mop using either method in the [README](../README.md#install) and make
sure `mop` is on your `PATH`. Start with an initialized vault and the relevant
third-party CLI installed. Each
`mop write` below prompts for a value; paste the actual credential at that prompt.
On subsequent updates, add `--replace`. The selected `.mopfile` must contain the referenced fields.
Run these commands from a logged-in Mac; secret access requires Touch ID or your
system password.

| What the application accepts | Use |
|---|---|
| Environment variables | `mop run -- COMMAND` |
| A password on stdin | Pipe `mop read` into the application |
| An open password file descriptor | Process substitution and `sshpass -d` |
| A configuration file | `mop inject --in-file ... --out-file ...` |
| A key or other multiline text file | `mop read --no-newline --out-file ...` |

## Use GitHub CLI without exporting a plaintext token

Store a GitHub token with the permissions your command needs:

```sh
mop write mop://personal/github/token
```

Supply a reference just for the command:

```sh
GH_TOKEN=mop://personal/github/token \
  mop run -- gh repo list --limit 10
```

GitHub CLI accepts [`GH_TOKEN`](https://cli.github.com/manual/gh_help_environment)
for authentication. The invoking shell never receives the resolved token in its
environment. It is available to `gh` and its descendants for their process
lifetimes; mop does not revoke the credential when they exit. Exact occurrences
printed to stdout/stderr are masked by default.

## Start a local application with several secrets

For a Node application that reads `PGUSER` and `PGPASSWORD` from its environment,
store the database fields:

```sh
mop write mop://development/database/username
mop write mop://development/database/password
```

Save this as `app.env`:

```dotenv
APP_ENV=development
PGHOST=localhost
PGPORT=5432
PGDATABASE=app
PGUSER=mop://${APP_ENV}/database/username
PGPASSWORD=mop://${APP_ENV}/database/password
```

From your application's directory, run its existing development script:

```sh
mop run --env-file app.env -- npm run dev
```

One authentication covers both fields. If either lookup fails, npm is not
launched. The reference file can be committed when it contains only references
and non-sensitive settings; the plaintext database credentials are never written
to it. They remain in the launched application's environment while it runs.

To select staging, first store the corresponding fields under `mop://staging/...`
and create `staging.env`:

```dotenv
APP_ENV=staging
PGHOST=staging-db.example.com
```

```sh
mop run --env-file app.env --env-file staging.env -- npm run dev
```

Later files override earlier files, then mop expands variables inside references
using the final environment. Thus both lookups select `staging`. The logical
names `development` and `staging` do not impose access permissions; use
[separate files](../README.md#file-boundaries-and-upgrades) for that.

For a program that needs normal terminal detection, use:

```sh
mop run --no-masking --env-file app.env -- npm run dev
```

This preserves direct terminal behavior but does not filter the program's output.

## Log in to a Docker registry using stdin

Store a registry access token, then replace `YOUR_DOCKER_USERNAME` below with your
Docker Hub username:

```sh
mop write mop://personal/docker/token
```

```bash
(
  set -o pipefail
  mop read mop://personal/docker/token --no-newline |
    docker login --username YOUR_DOCKER_USERNAME --password-stdin
)
```

Docker's [`--password-stdin`](https://docs.docker.com/reference/cli/docker/login/#provide-a-password-using-stdin---password-stdin)
receives the token without placing it in the command's arguments or an exported
variable. The subshell enables `pipefail` so a mop failure also makes the pipeline
fail. Pipeline commands start concurrently; this is not the resolve-before-launch
behavior of `mop run`.

Docker can persist the credential in its configured credential store after login;
the pipe only controls how it reaches Docker. See Docker's
[credential-store documentation](https://docs.docker.com/reference/cli/docker/login/#credential-stores).

## Generate a temporary npm configuration

Store an npm token:

```sh
mop write mop://personal/npm/token
```

Save this as `npmrc.template` in your project:

```ini
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken={{ mop://personal/npm/token }}
```

The registry-qualified token setting follows npm's
[authentication configuration](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/#auth-related-configuration).
Generate a private configuration, use it to identify the authenticated npm user,
and remove the generated file when the subshell exits:

```bash
(
  config_dir=$(mktemp -d "${TMPDIR:-/tmp}/mop-npm.XXXXXXXX") || exit
  trap 'rm -rf "$config_dir"' EXIT
  mop inject --in-file npmrc.template \
    --out-file "$config_dir/npmrc" --file-mode 0600 || exit
  npm --userconfig "$config_dir/npmrc" whoami
)
```

The `|| exit` stops the workflow if authentication, lookup, or file creation fails.
Commit the template, not the generated file. The generated file contains plaintext
while npm runs; cleanup is normal file deletion, not secure erasure, and a forced
process kill can prevent the exit trap from running.

`inject` inserts values literally. This example expects a single-line npm token.
It does not escape quotes, newlines, or delimiters for JSON, YAML, INI, or URLs.
For arbitrary values in structured configuration, use the target format's
serializer rather than concatenating an unescaped password into a template.

## Give sshpass a password through file descriptor 3

For a password-authenticated SSH profile already configured in `~/.ssh/config`,
store its single-line password:

```sh
mop write mop://personal/sshprofile/password
```

Use process substitution in Bash or zsh:

```bash
sshpass -d 3 ssh sshprofile 3< <(mop read mop://personal/sshprofile/password)
```

`<(mop read ...)` supplies a readable stream, `3<` connects that stream to file
descriptor 3 for this command, and `sshpass -d 3` reads the password from that
descriptor. The space between `3<` and `<(` is intentional. This keeps the password
out of command-line arguments and a long-lived `SSHPASS` environment variable,
without creating a plaintext password file. Standard input remains available for
the SSH session. The upstream
[sshpass manual](https://sources.debian.org/src/sshpass/1.09-1/sshpass.1/)
documents this inherited-descriptor interface and recommends pipe-based delivery.

Leave `mop read`'s default newline in place for this single-line password. Replace
`sshprofile` with your SSH host alias and use its normal host-key verification.
`sshpass` still handles the password in memory; this is a delivery mechanism, not
output masking. The redirection is scoped to this command rather than installed
with a persistent `exec 3< ...` in your shell.

Process substitution runs asynchronously: SSH can start before mop authentication
finishes, and the command's exit status does not report the substitution's exit
status. Cancelling mop supplies no password, but does not guarantee that SSH never
starts. Bash/zsh support this syntax; POSIX `sh` does not.

## Store and materialize a multiline SSH private key

For an existing key file, preserve its bytes through stdin:

```sh
mop write mop://personal/deploy/private-key < "$HOME/.ssh/existing_deploy_key"
```

Export it to a new, owner-only file before connecting:

```sh
mop read mop://personal/deploy/private-key --no-newline \
  --out-file "$HOME/.ssh/mop_deploy_key" --file-mode 0600 &&
  ssh -i "$HOME/.ssh/mop_deploy_key" deploy@example.com
```

The parent `.ssh` directory must already exist. `--no-newline` avoids adding a
byte to the stored value, and `&&` prevents SSH from starting if the read fails.
If the output file exists, mop refuses to replace it unless you explicitly add
`--force`. The exported key remains on disk until you remove it; a passphrase on
the key is still handled by SSH. This workflow stores UTF-8 key text and does not
provide an SSH agent, generate keys, or convert their formats.

For enrollment, recovery, rotation, and trust errors, see
[Security and key management](SECURITY.md).

## Adapt an existing op workflow

Use `mop://` references to fields explicitly stored in mop. There is no automatic
lookup in your 1Password account or Apple's Passwords app. The familiar `read`,
`run`, and `inject` workflows above do not imply identical dotenv syntax or flags:

- Expand variables only inside references, not in general dotenv values.
- Use `{{ mop://... }}` delimiters in templates; bare references remain literal.
- Use percent-encoded names, including `%20` for spaces.
- Select one encrypted file per command; use `--vault-file` or `MOP_VAULT_FILE`.

See the [CLI behavior reference](../README.md#secret-commands) for the precise
rules and [validation notes](VALIDATION.md) for what has been exercised. These
recipes have been checked for shell syntax; external account logins and SSH
connections are not part of the automated test suite.
