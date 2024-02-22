package fr.acinq.dnssec

import kotlin.test.Test
import kotlin.test.assertEquals

class ResourceRecordsTests {
    @Test
    fun dummy() {
        val rr = ResourceRecord(0)
        assertEquals("0", rr.print())
    }
}