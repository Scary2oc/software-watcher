# Restore / provision a new deployment

This restores **code**, not the previous machine or its private data. Do not copy
private directories into the checkout. Review the code, dependencies and storage
policy first. No command here enables a timer or publishes anything.

1. Provision the system requirements described in README through your normal,
   reviewed OS administration process. Run the offline suite before deployment.
   No dependency versions or prior installed-package inventory are supplied.
2. Choose a trusted source checkout and separate private state directory, normally
   `$HOME/.local/state/software-watcher`. Do not use a project/vault directory.
   Create private state directories as 0700 and their files as 0600. Provision
   `$HOME/.gnupg` as 0700 as well: even public-recipient encryption with
   `--no-autostart` requires an existing GnuPG home directory. Do not put a private
   key there merely to run this unattended scanner.
3. For a **new deployment**, generate or select a new encryption-capable recipient
   on a separately secured/offline key-management system. Verify the public key's
   identity, full fingerprint, expiry and encryption capability out of band.
   Export **only that public key** to `recipient.gpg` inside private state, not to
   the checkout. Keep the private key and its recovery copy in a separately
   secured location you control. Recover historical keys through your normal
   secure process only if historical decryption is needed. A new key cannot
   decrypt old ciphertext.
4. After owner approval of that exact public file, create its policy in private
   state. This snippet only reads the separately provisioned public file and
   records its approval digest; it does not generate, import or recover keys:

   ```sh
   /usr/bin/python3 -B - <<'PY'
   from pathlib import Path
   import hashlib, json, os
   os.umask(0o077)
   root = Path.home()/'.local/state/software-watcher'
   public = root/'recipient.gpg'
   if public.is_symlink() or not public.is_file():
       raise SystemExit('Provision and approve a public recipient first')
   public.chmod(0o600)
   policy = {'mode': 'gpg-public-recipient',
             'recipient_sha256': hashlib.sha256(public.read_bytes()).hexdigest()}
   # Exclusive creation: never silently replace a previous recipient approval.
   with (root/'storage-policy.json').open('x') as out:
       json.dump(policy, out)
   PY
   ```

5. From the checkout run the no-collection, no-network encryption preflight:

   ```sh
   /usr/bin/python3 -B -I -S daily_check.py --check-storage
   ```

   A missing recipient, changed digest or unusable GnuPG installation blocks
   collection with exit 4; unsafe storage also returns 4. Exit 3 means lock held.
   Exit 20 means a collection, feed, live-delivery or post-preflight encryption
   failure, or an unexpected runtime error. After collection starts, encrypted
   evidence may be incomplete; existing snapshots are not rolled back. Only an
   encryption-preflight failure explicitly guarantees `no collection performed`.
   `--check-storage` never processes notifications, even on failure; normal daily
   runs retain their sanitized failure-notification behavior. Uncertain
   applicability remains visible in counts even when the run itself succeeds.
6. Review `inventory.collect()` discovery roots and public feed coverage for this
   machine. Then run `daily_check.py` explicitly, using the same interpreter
   flags, only when local collection and public-feed downloads are approved.
   Without notification policy, only dry-run notification intent is recorded.
   Private detailed reports require owner decryption outside the checkout.
7. Optional notifications require a separately provisioned Hermes environment.
   Configure these process environment variables through a reviewed service
   configuration outside the checkout; no environment file is supplied:

   - `SOFTWARE_WATCHER_URGENT_TARGET`: explicit `platform:destination`.
   - `SOFTWARE_WATCHER_ROUTINE_TARGET`: explicit `platform:destination`.
   - `SOFTWARE_WATCHER_HERMES_PYTHON`: absolute existing Hermes interpreter.
   - `SOFTWARE_WATCHER_HERMES_HOME`: absolute reviewed Hermes profile directory.

   Keep `notification-policy.json` in private state with `{"mode":"dry-run"}`
   (or `disabled`) during review. Test against an explicitly approved sandbox,
   reconcile pending/ambiguous ledger events, then approve `{"mode":"live"}`
   separately. No live route is a default and no installer fallback exists.
8. `deploy/*.in` are generic systemd **user** templates. Replace `@SOURCE_DIR@`
   with a trusted absolute source directory, review all sandbox paths, calendar,
   dependencies and runtime environment, and validate with `systemd-analyze verify`
   on your target system. Do not use a shell, add an installer, or point the
   interpreter at an auto-repairing launcher. Keep the timer **disabled and not
   started** until manual storage, feed and optional sandbox checks are reviewed.
   The timer intentionally has no `[Install]` section and cannot auto-enable via
   these templates. Any later scheduling/installation is a separate owner action.

For the older release-review queue, construct a new private watchlist under the
checked state root. The supplied synthetic example is disabled and requires a
verified gocryptfs mount; never use it as real installed evidence. Legacy
plaintext reports/configuration and historical backups require separate review;
restoring this code does not migrate, delete or sanitize them.
