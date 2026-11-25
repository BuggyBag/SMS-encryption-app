# SecureSMS v3 - what changed vs v2 (multiple key sizes)

## Modes (enum `Mode`, code = character in the frame header)
| Mode | Code | Security (NIST) | Note |
|---|---|---|---|
| RSA-1024 | Q | ~80 bits | WEAK - only to compare with the papers |
| RSA-2048 | R | ~112 | original |
| RSA-3072 | S | ~128 (= P-256) | |
| RSA-4096 | T | ~140 | |
| ECC P-256 | E | ~128 | original |
| ECC P-384 | F | ~192 | |
| ECC P-521 | G | ~256 | |
R and E keep their old codes: v2 frames and saved state still work.

## Fair comparison (same security level)
RSA-3072 vs P-256 (128 bits), RSA-2048 vs P-224/P-256 (~112), P-384 ~ 192 (no RSA equivalent here; RSA-7680 would be needed).

## Real SMS cost (frame chars / SMS, 153 chars per segment), measured on the JVM
| Mode | KEY_EXCHANGE | SECURE_MESSAGE 32 B | 140 B | 400 B |
|---|---|---|---|---|
| RSA-1024 | 623 / 5 | 467 / 4 | 611 / 5 | 959 / 7 |
| RSA-2048 | 1139 / 8 | 807 / 6 | 951 / 7 | 1299 / 9 |
| RSA-3072 | 1651 / 11 | 1151 / 8 | 1295 / 9 | 1639 / 11 |
| RSA-4096 | 2163 / 15 | 1491 / 10 | 1635 / 11 | 1983 / 13 |
| P-256 | 331 / 3 | 307 / 3 | 451 / 3 | 795 / 6 |
| P-384 | 459 / 4 | 395 / 3 | 535 / 4 | 883 / 6 |
| P-521 | 603 / 4 | 487 / 4 | 631 / 5 | 979 / 7 |
(see the "Sizes" button for the exact list of every frame type).

## Message size limit per mode
`Messenger.maxPlaintext(mode)`: a frame must fit in 10 SMS (1530 chars). Original modes keep 400 bytes; RSA-3072 and RSA-4096 allow
much less (the frame carries one RSA block + one RSA signature). Longer messages are refused BEFORE any key exchange, with a clear message.

## Files touched
crypto/Basics.kt, crypto/Suites.kt (new), crypto/rsa/RsaSuite.kt, crypto/ecc/EccSuite.kt, messaging/Messenger.kt,
crypto/benchmark/{Benchmark,SizesAndSelfTest}.kt, ui/MainActivity.kt, res/layout/tab_keys.xml, res/values/strings.xml, tests (+KeySizesTest).
CSV now has extra columns `family,key_bits` after `scheme`.

## Warnings
* Verified: pure-Kotlin core on a desktop JVM (47 tests, 0 failures). NOT verified: UI/XML (not compiled), Android Conscrypt, a real phone.
* Sandbox timings are not valid for a phone; run the benchmark on the device. RSA-3072/4096 key generation is slow on phones (it uses fewer repetitions).
* RSA-3072/4096 over real SMS cost many messages: demo them on emulators.
