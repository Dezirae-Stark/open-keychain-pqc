# OpenKeychain PQC v6.0.4-pqc.4

Cosmetic release: a distinct visual identity for this fork, plus a real bug
fix uncovered while verifying it. No cryptographic, key-generation, or
import/export code changed — if you're only here for that, v6.0.4-pqc.3 is
functionally identical.

## New: violet/cyan/magenta theme

Previously this app used stock OpenKeychain's green branding end to end —
the only difference from classic OpenKeychain was the app label. That made
it easy to mix up the two apps at a glance, especially in the app switcher
or launcher. This release gives the PQC fork its own visual identity:
midnight violet base, electric cyan accent, and magenta reserved as a
single signature highlight (the "add key" FAB) rather than spread across
the whole UI. Red is untouched and still means exactly what it always
did — key-health warnings, the standalone-PQC non-interop dialog — not
repurposed as a general accent.

Covers every brand surface:
- Launcher icon — both the modern adaptive-icon vector background and the
  legacy pre-Android-8 flat PNG fallbacks, across all five densities
- Light and Dark in-app themes, including dialogs
- The navigation drawer header image and its embedded logo mark
- The onboarding "create/import key" mascot graphic

Debug builds keep OpenKeychain's existing indigo debug-icon convention
(lets you tell a debug install apart from a release install at a glance) —
that predates this fork and wasn't touched.

## Fix: main "add key" FAB ignored the theme's accent color

While verifying the new theme on-device, found that `key_list_fragment.xml`
had its floating action button hardcoded to `?attr/colorPrimary` instead of
the theme's `colorFab` attribute — so the app's most prominent button never
picked up the intended accent color under *any* theme, old or new. Fixed by
pointing it at `colorFab`/`colorFabPressed` like the rest of the app's FABs
already do.

## Verification

Built as a signed release APK (not just debug) and checked on-device:
launcher icon color (confirmed the debug variant's stale-looking icon was
actually a separate, correctly-untouched asset, not a bug), Light theme,
Dark theme (via forced system dark mode), the nav drawer header, and the
FAB fix. Full unit test suite re-run, no regressions.

## Signing

Signed with the same dedicated release key as prior PQC releases
(`CN=OpenKeychain PQC, OU=Obsidian Circuit, O=Dezirae Stark`), package
`org.sufficientlysecure.keychain.pqc`. Installs as a straight update over
v6.0.4-pqc.1/.2/.3 — no data loss, no uninstall needed.
