package fr.acinq.dnssec

/**
 * A valid domain name must:
 *  - end with a "."
 *  - consist only of printable ASCII characters
 *  - contain at most 255 characters
 *  - each label may contain at most 63 characters
 */
data class DomainName(val name: String) {
    /** Encode a domain name as a sequence of length-prefixed labels. */
    fun encode(): ByteArray = when {
        name == "." -> byteArrayOf(0)
        else -> {
            val labels = name.lowercase().split('.').map { it.encodeToByteArray() }
            val result = ByteArray(labels.sumOf { 1 + it.size })
            var offset = 0
            labels.forEach { label ->
                result[offset] = label.size.toByte()
                offset += 1
                label.copyInto(result, offset)
                offset += label.size
            }
            result
        }
    }

    companion object {
        fun fromString(name: String): DomainName? = when {
            name.isEmpty() -> null
            name.last() != '.' -> null
            name.length > 255 -> null
            name.any { it == '"' || it.code > 126 || it.code < 33 } -> null
            name.split('.').any { it.length > 63 } -> null
            else -> DomainName(name)
        }
    }
}

/** Time-To-Live: how long a [ResourceRecord] can be cached before it should be queried again. */
data class TTL(val value: UInt)

/**
 * Resource Records are the fundamental type in the DNS: individual records mapping a name to some data.
 * We only support records that are needed to generate and validate TXT or TLSA record proofs.
 */
sealed class ResourceRecord {
    /** The resource record type, as maintained by IANA: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4. */
    abstract val type: UShort

    /** The domain name this record is at. */
    abstract val name: DomainName

    /** Encodes the data part of this record, prefixed by its two-bytes length (in big-endian byte order). */
    abstract fun encodeLengthPrefixedData(): ByteArray

    /**
     * An IPv4 Address resource record.
     *
     * @param address the 4 bytes of the IPv4 address.
     */
    data class A(override val name: DomainName, val address: ByteArray) : ResourceRecord() {
        override val type: UShort = 1U
        override fun encodeLengthPrefixedData(): ByteArray {
            val result = createLengthPrefixedArray(4)
            address.copyInto(result, destinationOffset = 2)
            return result
        }
    }

    /**
     * An IPv6 Address resource record.
     *
     * @param address the 16 bytes of the IPv6 address.
     */
    data class AAAA(override val name: DomainName, val address: ByteArray) : ResourceRecord() {
        override val type: UShort = 28U
        override fun encodeLengthPrefixedData(): ByteArray {
            val result = createLengthPrefixedArray(16)
            address.copyInto(result, destinationOffset = 2)
            return result
        }
    }

    /**
     * A Canonical Name resource record, referring all queries for this name to another name.
     *
     * @param canonicalName resolvers should use this name when looking up any further records for [name].
     */
    data class CName(override val name: DomainName, val canonicalName: DomainName) : ResourceRecord() {
        override val type: UShort = 5U
        override fun encodeLengthPrefixedData(): ByteArray {
            val encodedName = canonicalName.encode()
            val result = createLengthPrefixedArray(encodedName.size)
            encodedName.copyInto(result, 2)
            return result
        }
    }

    /**
     * A Delegation Name resource record, referring all queries for subdomains of this name to another subtree of the DNS.
     *
     * @param delegationName resolvers should use this domain name tree when looking up any further records for subdomains of [name].
     */
    data class DName(override val name: DomainName, val delegationName: DomainName) : ResourceRecord() {
        override val type: UShort = 39U
        override fun encodeLengthPrefixedData(): ByteArray {
            val encodedName = delegationName.encode()
            val result = createLengthPrefixedArray(encodedName.size)
            encodedName.copyInto(result, 2)
            return result
        }
    }

    /**
     * A public key resource record which can be used to validate [RRSig]s.
     *
     * @param flags flags which constrain the usage of this public key.
     * @param protocol the protocol this key is used for (protocol `3` is DNSSEC).
     * @param alg the algorithm which this public key uses to sign data.
     * @param publicKey the public key itself.
     */
    data class DnsKey(override val name: DomainName, val flags: UShort, val protocol: Byte, val alg: Byte, val publicKey: ByteArray) : ResourceRecord() {
        override val type: UShort = 48U
        override fun encodeLengthPrefixedData(): ByteArray {
            val result = createLengthPrefixedArray(2 + 1 + 1 + publicKey.size)
            writeBigEndian(flags, result, offset = 2)
            result[4] = protocol
            result[5] = alg
            publicKey.copyInto(result, 6)
            return result
        }
    }

    /**
     * A Delegation Signer resource record which indicates that some alternative [DnsKey] can sign for records in the zone which matches [name].
     *
     * @param name zone that a [DnsKey] which matches the [digest] can sign for.
     * @param keyTag a short tag which describes the matching [DnsKey].
     * @param alg the algorithm which the [DnsKey] referred to by this [DS] uses.
     * @param digestType the type of digest used to hash the referred-to [DnsKey].
     * @param digest the digest itself.
     */
    data class DS(override val name: DomainName, val keyTag: UShort, val alg: Byte, val digestType: Byte, val digest: ByteArray) : ResourceRecord() {
        override val type: UShort = 43U
        override fun encodeLengthPrefixedData(): ByteArray {
            val result = createLengthPrefixedArray(2 + 1 + 1 + digest.size)
            writeBigEndian(keyTag, result, offset = 2)
            result[4] = alg
            result[5] = digestType
            digest.copyInto(result, 6)
            return result
        }
    }

    /**
     * A Name Server resource record, which indicates the server responsible for handling queries for a zone.
     *
     * @param nameServer the name of the server which is responsible for handling queries for the [name] zone.
     */
    data class NS(override val name: DomainName, val nameServer: DomainName) : ResourceRecord() {
        override val type: UShort = 2U
        override fun encodeLengthPrefixedData(): ByteArray {
            val encodedNameServer = nameServer.encode()
            val result = createLengthPrefixedArray(encodedNameServer.size)
            encodedNameServer.copyInto(result, destinationOffset = 2)
            return result
        }
    }

    /**
     * A Resource Record (set) signature resource record. This contains a signature over all the resource records of the given type at the given name.
     *
     * @param name the name of any records which this signature is covering (ignoring wildcards).
     * @param typeCovered the resource record type which this [RRSig] is signing: all resources records of this type at the same name as [name] must be signed by this [RRSig].
     * @param alg the algorithm which is being used to sign: this must match the [DnsKey.alg] field in the [DnsKey] being used to sign.
     * @param labels the number of labels in the name of the records that this signature is signing: if this is less than the number of labels in [name], this signature is covering a wildcard entry.
     * @param originalTTL the TTL of the records which this [RRSig] is signing.
     * @param expiration the expiration (as a UNIX timestamp) of this signature.
     * @param inception the time (as a UNIX timestamp) at which this signature becomes valid.
     * @param keyTag a short tag which describes the matching [DnsKey].
     * @param signerName the [DnsKey.name] in the [DnsKey] which created this signature: this must be a parent of [name].
     * @param signature the signature itself.
     */
    data class RRSig(
        override val name: DomainName,
        val typeCovered: UShort,
        val alg: Byte,
        val labels: Byte,
        val originalTTL: UInt,
        val expiration: UInt,
        val inception: UInt,
        val keyTag: UShort,
        val signerName: DomainName,
        val signature: ByteArray
    ) : ResourceRecord() {
        override val type: UShort = 46U
        override fun encodeLengthPrefixedData(): ByteArray {
            val encodedSignerName = signerName.encode()
            val result = createLengthPrefixedArray(2 + 1 + 1 + 4 * 3 + 2 + encodedSignerName.size + signature.size)
            writeBigEndian(typeCovered, result, offset = 2)
            result[4] = alg
            result[5] = labels
            writeBigEndian(originalTTL, result, offset = 6)
            writeBigEndian(expiration, result, offset = 10)
            writeBigEndian(inception, result, offset = 14)
            writeBigEndian(keyTag, result, offset = 18)
            encodedSignerName.copyInto(result, destinationOffset = 20)
            signature.copyInto(result, destinationOffset = 20 + encodedSignerName.size)
            return result
        }
    }

    /**
     * A TLS Certificate Association record containing information about the TLS certificate which should be expected when communicating with the host at the given name.
     * See <https://www.rfc-editor.org/rfc/rfc6698.html> for more information.
     *
     * @param certUsage the type of constraint on the TLS certificate(s) used which should be enforced by this record.
     * @param selector whether to match on the full certificate, or only the public key.
     * @param matchingType the type of data included which is used to match the TLS certificate(s).
     * @param data the certificate data or hash of the certificate data itself.
     */
    data class TLSA(override val name: DomainName, val certUsage: Byte, val selector: Byte, val matchingType: Byte, val data: ByteArray) : ResourceRecord() {
        override val type: UShort = 52U
        override fun encodeLengthPrefixedData(): ByteArray {
            val result = createLengthPrefixedArray(3 + data.size)
            result[2] = certUsage
            result[3] = selector
            result[4] = matchingType
            data.copyInto(result, 5)
            return result
        }
    }

    /**
     * A DNS TXT record, used to associate arbitrary text with a host or other name.
     *
     * @param data the text record itself: it is generally a valid UTF-8 string, but it is not a requirement, so we use an arbitrary series of bytes here.
     */
    data class Txt(override val name: DomainName, val data: ByteArray) : ResourceRecord() {
        override val type: UShort = 16U
        override fun encodeLengthPrefixedData(): ByteArray {
            // The RDATA for a TXT record is a list of chunks of at most 255 bytes, each chunk prefixed by its 1-byte length.
            val chunksCount = (data.size + 254) / 255
            val result = createLengthPrefixedArray(data.size + chunksCount)
            var offset = 2
            (0 until chunksCount).forEach { i ->
                val chunkSize = minOf(data.size - 255 * i, 255)
                result[offset] = chunkSize.toByte()
                offset += 1
                data.copyInto(result, offset, 255 * i, 255 * i + chunkSize)
                offset += chunkSize
            }
            return result
        }
    }

    companion object {
        private fun createLengthPrefixedArray(rdataSize: Int): ByteArray {
            val result = ByteArray(2 + rdataSize)
            result[0] = rdataSize.shr(8).toByte()
            result[1] = rdataSize.toByte()
            return result
        }

        private fun writeBigEndian(u16: UShort, out: ByteArray, offset: Int) {
            out[offset] = u16.toInt().shr(8).toByte()
            out[offset + 1] = u16.toByte()
        }

        private fun writeBigEndian(u32: UInt, out: ByteArray, offset: Int) {
            out[offset] = u32.shr(24).toByte()
            out[offset + 1] = u32.shr(16).toByte()
            out[offset + 2] = u32.shr(8).toByte()
            out[offset + 3] = u32.toByte()
        }
    }
}