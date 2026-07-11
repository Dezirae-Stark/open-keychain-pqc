# OpenKeychain PQC v6.0.4-pqc.5

Follow-up to v6.0.4-pqc.4: finishes the theme rebrand. Found by the user
checking their own key on-device — the key-detail screen's header was
still green. No cryptographic, key-generation, or import/export code
changed.

## Fix: key-detail header, and the app's "healthy" status color, were still green

Two separate bugs, both green:

1. `view_key_activity.xml`'s header (the collapsing toolbar behind the QR
   code) was hardcoded to the literal `@color/primary` resource instead of
   the `?attr/colorPrimary` theme attribute — the same class of bug fixed
   for the main FAB in pqc.4.

2. Fixing that alone didn't change anything visible, because that header's
   real-world color isn't chrome at all: `ViewKeyActivity.java` sets it
   programmatically based on key health (green/orange/red — the same
   traffic-light convention used for encrypt/decrypt results and signature
   verification throughout the app), overriding the XML default the moment
   the health check resolves.

Per an explicit decision on how far to take the rebrand: went with full
cohesion over preserving the stock green-means-healthy convention. Green
does not appear anywhere in this fork's UI now — the "healthy/verified"
status family (`key_flag_green`, `android_green_light`/`_dark`,
`card_view_button` — all the literal same green under different names
upstream) now resolves to a cyan in the same family as the FAB/accent
palette. Red and orange (caution/bad) are untouched. Also fixed
`KeyStatusList`'s OK/DIVERT text color, which was wired to
`R.color.primary` rather than the status color its own icon uses —
invisible upstream only because they happened to share the same green
value; not invisible anymore once primary became violet.

## Verification

Created a real key on-device and opened its detail screen to confirm the
header now renders cyan for a healthy key, matching the checkmark and the
rest of the palette. Full unit test suite re-run, no regressions.

## Signing

Signed with the same dedicated release key as prior PQC releases
(`CN=OpenKeychain PQC, OU=Obsidian Circuit, O=Dezirae Stark`), package
`org.sufficientlysecure.keychain.pqc`. Installs as a straight update over
any prior pqc release — no data loss, no uninstall needed.
