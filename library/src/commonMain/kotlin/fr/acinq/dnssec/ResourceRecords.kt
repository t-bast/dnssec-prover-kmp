package fr.acinq.dnssec

data class ResourceRecord(val type: Int) {
    fun print(): String = type.toString()
}