# Removing a secret from git history

Do this **after** rotating the credential, never instead of it. Clones,
forks, CI caches and anyone who fetched in the meantime keep the old commits.

## Not pushed yet

The secret only exists in local commits, so rewrite them before pushing:

- Last commit: fix the file, `git add` it, then `git commit --amend`.
- Older unpushed commit: `git rebase -i <upstream>` and edit that commit, or
  squash the fix into it.
- Confirm: `mcp-secret-sentinel scan --range` (or the `scan_git_range` tool)
  must come back clean before pushing.

## Already pushed

Rewriting published history disrupts everyone who has the branch. Agree on
it with the repository owner first, and confirm with the user before any
force-push.

1. Make a fresh mirror clone and a backup:
   `git clone --mirror <url> repo.git`
2. Replace the value with [git filter-repo](https://github.com/newren/git-filter-repo)
   (install with `pipx install git-filter-repo`). Put the literal in a local
   file that you never commit, one rule per line, `literal==>replacement`:
   `printf '%s==>REMOVED\n' "$OLD_VALUE" > ../replacements.txt`
   then `git filter-repo --replace-text ../replacements.txt`.
   To drop a whole file instead: `git filter-repo --invert-paths --path path/to/file`.
3. Check the result with `mcp-secret-sentinel scan --history 1000 --all-branches`.
4. Push the rewritten refs: `git push --force --mirror` (or per branch with
   `--force-with-lease`), then delete `replacements.txt`.
5. Everyone with a clone must re-clone or hard-reset to the new history; a
   stale clone that pushes brings the secret back.

## Hosting provider caches

- GitHub keeps unreachable commits reachable by SHA for a while, and pull
  request refs keep old commits. For sensitive data, follow GitHub's
  "Removing sensitive data from a repository" guide, which explains how to ask
  GitHub Support to purge cached views and PR refs.
- Forks are separate repositories; their owners must clean them.
- Turn on push protection (GitHub secret scanning) or the secret-sentinel
  pre-commit hook so the next one is stopped before it is published.
