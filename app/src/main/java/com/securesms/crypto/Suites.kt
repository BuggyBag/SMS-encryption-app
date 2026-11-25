package com.securesms.crypto

import com.securesms.crypto.ecc.EccSuite
import com.securesms.crypto.ecc.EccSuiteImpl
import com.securesms.crypto.rsa.RsaSuite
import com.securesms.crypto.rsa.RsaSuiteImpl

/** Registry: one [Suite] per [Mode]. Everything that used to pick between RsaSuite and EccSuite goes through here. */
object Suites {
    private val byMode: Map<Mode, Suite> = Mode.entries.associateWith { m ->
        when (m) {
            Mode.RSA -> RsaSuite          // the original singletons
            Mode.ECC -> EccSuite
            else -> if (m.family == Family.RSA) RsaSuiteImpl(m) else EccSuiteImpl(m)
        }
    }

    fun of(m: Mode): Suite = byMode.getValue(m)

    /** All suites, in [Mode] order (the order used by the spinners, benchmark and CSV). */
    val all: List<Suite> get() = Mode.entries.map { of(it) }
}
