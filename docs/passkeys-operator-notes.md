# Passkeys: operator notes

## An account left with no way in after a passkey removal

### What can happen

Removing a passkey on MongoDB is two steps, because the account and its
passkeys live in two collections
(`delete_passkey_unless_last_way_in` in
`crates/core/database/src/models/passkeys/ops/mongodb.rs`):

1. the passkey row is deleted;
2. the account is looked at again, and if it was left with no way in, the
   row is put back.

Between the two steps the removed row is held only in the memory of the
process. Two things can leave the account with no way in:

- The put-back fails twice. This is logged, with the account id:

  ```
  passkeys: could not put back the last passkey of account <id> after a removal race
  ```

- The process dies between the delete and the put-back. Nothing is logged.

So the log line finds the first case only. The sweep below finds both.

### Finding the accounts

"No way in" means: no linked Google or Apple sign-in, no password that can
be used (no password at all, or a password on an account with no email to
sign in with), and no passkey. Disabled accounts are left out, and so are
accounts that are deleted or scheduled for deletion. An account whose
deletion still waits for the confirmation mail is kept in: it is a live
account, and its stored `deletion` is not `null`, so a filter on
`deletion: null` would miss it.

```js
db.accounts.aggregate([
  { $match: { google_id: null, apple_id: null,
      "deletion.status": { $nin: ["Scheduled", "Deleted"] }, disabled: { $ne: true },
      $or: [ { password_absent: true }, { email_absent: true }, { email: /@noemail\.invalid$/i } ] } },
  { $lookup: { from: "passkeys", localField: "_id", foreignField: "user_id", as: "pk" } },
  { $match: { pk: { $size: 0 } } },
  { $project: { _id: 1, email_absent: 1, password_absent: 1 } } ])
```

Every row it returns is an account that cannot sign in. Not all of them got
there through a removal race: an account that was made through Google or
Apple, never set a password and had its link removed shows up here too.
The repair is the same.

### Repair

Which repair applies depends on whether the account has an email address.

**The account has an email** (`email_absent` is `false`, and `email` is not
at `noemail.invalid`). Write nothing. The owner uses "Forgot password" on
the sign-in page and sets a password with the mailed link. The lost-passkey
recovery does not help here: it refuses an account that has zero passkeys.

**The account has no email** (`email_absent` is `true`, or `email` is at
`noemail.invalid`). The only repair is the one row the race removed, taken
from the newest backup that still has it.

Put back that one row and no other. A backup can hold passkeys of the
account that the owner removed on purpose afterwards (a lost phone, a
device given away). Inserting every row the backup has for the account
would hand those back as working ways in.

1. In the restored copy of the backup, list the account's rows:

   ```js
   db.passkeys.find({ user_id: "<id>" }).sort({ last_used_at: -1 })
   ```

2. Pick the row that was lost. It is the last passkey the account had, so:

   - if the log line above was written for this account, take its time.
     The row was made before it (`created_at`) and is the one used last
     before it (`last_used_at`);
   - if there is no log line (the process died), take the row with the
     newest `last_used_at`; a row that was never used has no
     `last_used_at`, then go by the newest `created_at`.

   If the backup has more than one row and these do not single one out,
   stop. Which passkey to give back is then the owner's decision, as in
   the last paragraph of this section.

3. On the live database, insert that one document exactly as it is:

   ```js
   db.passkeys.insertOne(<that document, unchanged>)
   ```

   Do not edit any field. The unique indexes on `_id` and `credential_id`
   refuse a second insert of the same row, so running this twice does no
   harm. The signature counter inside the row may be older than the last
   one the passkey reached; that is accepted, the next sign-in moves it
   forward.

4. Run the sweep again. The account must be gone from the result.

If no backup has the row, the account cannot be given back by a database
write: nothing in the database proves who owns an account that has no
email and no passkey. What to do then is the owner's decision, case by
case.

## An invite used up by an account that does not exist

### What can happen

With `registration.invite_only` on, a sign-up takes its invite first and
makes the account second: the invite is marked `used` and `claimed_by` is
set to the id the account is going to get. Three things leave an invite
claimed by an id that has no account:

- The process dies between the claim and the creation. Nothing is logged.
- The creation fails and it cannot be told whether the account was stored
  (the read that would tell fails as well). The invite is then kept on
  purpose: giving it back while the account exists would let one invite
  make two accounts.
- A password sign-up names an address that already has an account. No
  account is made, and the invite stays used on purpose: if it were given
  back, the invite would tell its holder that the address is registered.
  This one is not a fault.

The rows look the same in all three cases.

### Finding the invites

```js
db.account_invites.aggregate([
  { $match: { used: true, claimed_by: { $type: "string" } } },
  { $lookup: { from: "accounts", localField: "claimed_by", foreignField: "_id", as: "account" } },
  { $match: { account: { $size: 0 } } },
  { $project: { _id: 1, claimed_by: 1 } } ])
```

A deleted account keeps its row in `accounts`, so an invite a deleted
account used is not listed. `claimed_by` is a ULID: its first ten
characters are the time of the claim. Leave alone any invite claimed in
the last few minutes, its sign-up may still be running.

### Repair

Free an invite only when the person it was given to reports that it does
not work and has no account. That person can have been the third case
above; freeing the invite is then still the right answer to them, and it
is given by hand, not by the sign-up route.

```js
db.account_invites.updateOne(
  { _id: "<invite>", used: true, claimed_by: "<claimed_by from the query>" },
  { $unset: { used: "", claimed_by: "" } })
```

`$unset` of both fields, not `$set`: an unused invite is stored without
either field. The filter names `claimed_by`, so an invite that another
sign-up has taken in the meantime is left alone. `modifiedCount` must be 1.

## What was checked, and what was not

Nothing in this file was run against the production database.

Reported by the session that wrote the first version of this file, on
2026-11-23: the sweep as it was then written (with `deletion: null` where
the filter on `deletion.status` now stands), the `find` on `passkeys`, the
`insertOne` and the two index refusals were run on the local development
MongoDB, in scratch databases that session created and dropped, with
accounts in each state. The sweep listed the accounts with no way in and
no others, and stopped listing an account once its row was inserted again.

Not run anywhere yet: the sweep with the `deletion.status` filter, the
sorted `find`, and both statements of the invite section. Run them on a
scratch database before relying on them.
