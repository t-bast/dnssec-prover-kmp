package fr.acinq.dnssec

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ResourceRecordsTests {
    @Test
    fun `parse valid domain names`() {
        val validDomains = listOf(
            "www.example.com.",
            "a.b.c.",
            "test!.s0#.co~m.",
        )
        validDomains.forEach { name -> assertNotNull(DomainName.fromString(name)) }
    }

    @Test
    fun `reject invalid domain names`() {
        val invalidDomains = listOf(
            "", // empty
            "www.example.com", // not ending with '.'
            "www.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.", // too long
            "www.éxample.com.", // non-printable ascii
            "www.\"example\".com.", // '"' is disallowed
            "www.labels-cannot-be-too-loooooooooooooooooooooooooooooooooooooooong.com.", // labels are limited to at most 63 characters
        )
        invalidDomains.forEach { name -> assertNull(DomainName.fromString(name)) }
    }
}