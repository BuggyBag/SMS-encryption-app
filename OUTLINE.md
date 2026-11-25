# SecureSMS v2 — project outline (starting point)

A merge of two projects:
* **SmsCrypto** (classmate): Gradle/Android Studio setup, plain XML screen style, benchmark mindset, SMS-size analysis, in-app self-test.
* **SecureSMS** (yours): signed/authenticated key exchange, fingerprint trust, per-message RSA/ECC hybrid encryption, replay protection, encrypted storage, 37 passing unit tests.

Goal of v2: keep the strong security core, but make the app **simple to read, run and extend** on a college budget (two phones, no server).

## 1. Status — what is and isn't verified
| Part | Status |
|---|---|
| `crypto/`, `protocol/`, `messaging/`, `storage/Store` (pure Kotlin) | Compiled and tested on a JVM: **37/37 unit tests pass** (includes a two-phone simulation and attack cases). |
| Android UI (XML + `MainActivity`), `AndroidSms`, `AndroidVault`, Gradle | **Written, not compiled** (no Android SDK available when it was produced). Gradle files are copied from your classmate's working project, so it should open in the same Android Studio. Expect small fixes on first build. |
| Two-phone SMS, Keystore, Conscrypt RSA-OAEP/PSS | Not tested on hardware. The **Self-test** button on the RSA vs ECC tab checks the crypto support on the phone. |

## 2. Screen layout (classmate's XML style, your tabs)
One activity, one `TabLayout`, three included XML layouts (`tab_chat`, `tab_compare`, `tab_keys`). Same widgets as the SmsCrypto screen (Spinner, EditText, Buttons, monospace log) — no Compose, no fragments.

| Tab | Contents |
|---|---|
| **Chat** | Mode spinner (RSA-2048 / ECC P-256) · phone · security status line · Verify fingerprint / Restart key exchange / Retry failed · transcript (shows mode and status per message) · message box · Send |
| **RSA vs ECC** | Benchmark · Self-test · SMS sizes · Export raw/summary CSV · "real messages" switch · progress bar · text bar charts + statistics table |
| **My keys** | My RSA and ECC fingerprints (read them to your contact by voice) · Rotate key |

All UI text is in `res/values/strings.xml` (change/translate there).

## 3. Code map
```
app/src/main/java/com/securesms/
├── SecureSmsApp.kt            owns Store + Messenger (so SMS works with the app closed)
├── ui/MainActivity.kt         the 3 tabs (only file that touches views)
├── messaging/Messenger.kt     protocol state machine: handshake, send, receive, trust, retry, rotate
├── protocol/Frame.kt          wire format  SSMS|ver|mode|type|session|msgId|base64(fields,signature)
├── crypto/
│   ├── Suite.kt               interface shared by both modes
│   ├── rsa/RsaSuite.kt        RSA-2048: OAEP-SHA256 wrap, PSS signatures
│   ├── ecc/EccSuite.kt        P-256: ephemeral ECDH, ECDSA, on-curve validation
│   ├── symmetric/Symmetric.kt AES-256-GCM + HKDF-SHA-256 (shared by both modes)
│   └── benchmark/             Benchmark.kt (timings, stats, CSV)  ·  SizesAndSelfTest.kt (new)
├── storage/                   Models, Store (encrypted state file), AndroidStorage (Keystore AES key)
└── sms/AndroidSms.kt          send (multipart), receive, delivery callbacks
app/src/test/                  CryptoTest.kt, MessengerTest.kt (JUnit4, no Android needed)
```
Rule of thumb for the team: **anything with `android.` imports stays in `ui/`, `sms/`, `storage/AndroidStorage.kt`, `SecureSmsApp.kt`; everything else stays pure Kotlin** so it can be unit tested.

## 4. How a first message works
```
Alice: Send                      Bob
  no session -> queue message
  KEY_REQUEST (signed) ---------->  verify signature, auto-reply (public key only)
  <--------- KEY_RESPONSE (signed)
  Alice sees Bob's fingerprint
  Alice + Bob compare by voice, each taps Trust
  KEY_CONFIRM ------------------->  confirm keys match
  SECURE_MESSAGE (encrypted) ----->  verify signature, decrypt, show
Later messages: just SECURE_MESSAGE (1 SMS burst each way, no handshake)
```
Never plaintext: failures mark the message FAILED/REJECTED with a reason and offer Retry.

## 5. Real SMS cost (computed from real frames; GSM-7)
| Frame | RSA-2048 | ECC P-256 |
|---|---|---|
| KEY_REQUEST | 6 SMS | 3 SMS |
| KEY_RESPONSE | 8 SMS | 3 SMS |
| KEY_CONFIRM | 3 SMS | 2 SMS |
| SECURE_MESSAGE, 32 B | 6 SMS | 3 SMS |
| SECURE_MESSAGE, 140 B | 7 SMS | 3 SMS |
| SECURE_MESSAGE, 400 B | 9 SMS | 6 SMS |

This is a real finding for the report: RSA's handshake and per-message overhead cost 2-3x more SMS than ECC. (Segment counts count `|` as 2 septets; the **SMS sizes** button reproduces this table on the phone.)

## 6. Roadmap — how to make it better
**A. Needed before you hand it in**
1. Build in Android Studio, fix compile errors (likely small: imports, resource names).
2. Press **Self-test** on both phones → must say PASSED (proves OAEP-SHA256 and PSS work on your phones).
3. Run the two-phone test plan (section 7) and record results.
4. Run **Benchmark** on both phones; export CSV; use the real numbers in your report (the sandbox numbers are not valid for phones).

**B. Good upgrades, low effort**
5. Add a "Local mode" (classmate's idea) so one phone/emulator can demo without a second device: a loopback `SmsTransport` that feeds a second in-memory `Messenger`. See the test harness `Net`/`Phone` in `MessengerTest.kt`.
6. Contacts list (the data already exists: `Messenger.contacts()`), instead of typing the number every time.
7. Add size columns (bytes / SMS count) to the benchmark CSV using `Sizes.report()`.
8. Show per-message crypto time under each received message (the live samples already store it).
9. Message length counter next to the message box (limit is 400 bytes).

**C. Stretch (only if time allows)**
10. Compressed EC points (33 B instead of 65 B) to save SMS — classmate's `ECIES.compress/decompress` is a reference.
11. Separate RSA keys for encryption and signing.
12. DONE (v3): key sizes RSA 1024/2048/3072/4096 and ECC P-256/384/521 in chat, benchmark, CSV, sizes report and My keys. See CHANGES_v3.md.
13. Replace tab visibility toggling with `ViewPager2` + fragments.

## 7. Two-phone test plan (fill in results yourself)
| # | Test | Expected |
|---|---|---|
| 1 | Self-test on both phones | PASSED |
| 2 | First RSA message | key exchange, both Trust, message arrives |
| 3 | Second RSA message / reply | no handshake |
| 4 | First + second ECC message | same, fewer SMS |
| 5 | Switch RSA↔ECC in the same chat | each decrypts; receiver never picks the mode |
| 6 | Airplane mode on receiver during request | stays "waiting"; Restart key exchange works |
| 7 | Fingerprint mismatch | Reject |
| 8 | Force-stop app with a queued message, reopen | still queued |
| 9 | Reinstall app on one phone | red "key CHANGED" warning |
| 10 | Benchmark on both phones, export CSV | real data |

## 8. Known limitations (keep in the report)
* Manual fingerprint check per contact **and per mode**. Phone numbers matched by last 10 digits.
* If a handshake SMS fails to send, the UI only shows "waiting" (use Restart).
* Encrypted `SSMS|…` text also shows up in the phone's normal Messages app.
* Identity keys are software keys stored inside a state file encrypted by an Android Keystore AES key (not Keystore RSA/EC keys, which are inconsistent across API levels).
* RSA mode has no forward secrecy per message; ECC mode only partly (see v1 README notes).
* `minSdk` is 26 (the classmate used 24) because `java.util.Base64` needs it.
