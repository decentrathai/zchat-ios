// PAR-0002: ZMSG v4 builders, byte-aware chunking and the single-memo recognisers, as Android 2.13.0
// (UI/screen/chat/model/ZMSGProtocol.kt at 479a084d3; census CENSUS1_WIRE_v2.13.0.md section 1).
// Only formats iOS emits are built here (v4); v2/v3 are parsed only (no dormant code).

public enum ZMSGProtocol {
    typealias P = ZMSGConstants.Prefixes
    typealias M = ZMSGConstants.Markers

    // MARK: - Hashes and conversation ids (:130-184)

    /// First 8 bytes of SHA-256(UTF-8 address), 16 lowercase hex (:146-151).
    public static func generateAddressHash(_ address: String) -> String {
        lowercaseHex(sha256(Array(address.utf8)).prefix(8))
    }

    /// Legacy form: first 6 bytes, 12 lowercase hex (:165-169).
    public static func generateLegacyAddressHash(_ address: String) -> String {
        lowercaseHex(sha256(Array(address.utf8)).prefix(6))
    }

    /// `hash.length == 12 && hash.all { it.isDigit() || it in 'a'..'f' }` (:157-159). Kotlin `isDigit` is any Nd digit.
    public static func isLegacyHash(_ hash: String) -> Bool {
        let u = KS.units(hash)
        return u.count == ZMSGConstants.hashLength && u.allSatisfy { KS.isDigit($0) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    /// 8 characters of CONV_ID_CHARS from the system CSPRNG (:179-184, SecureRandom on Android).
    public static func generateConversationId() -> String {
        let alphabet = Array(ZMSGConstants.convIdChars.unicodeScalars)
        var rng = SystemRandomNumberGenerator()
        var view = String.UnicodeScalarView()
        for _ in 0..<ZMSGConstants.convIdLength {
            view.append(alphabet[Int.random(in: 0..<alphabet.count, using: &rng)])
        }
        return String(view)
    }

    /// validateConvId (:130-137): exactly 8 UTF-16 units, each in CONV_ID_CHARS.
    static func validateConvId(_ convId: String) throws {
        let u = KS.units(convId)
        guard u.count == ZMSGConstants.convIdLength, u.allSatisfy({ KS.isConvIdChar($0) }) else {
            throw ZMSGError.invalidConversationId
        }
    }

    // MARK: - Single-memo v4 builders (:235-458)

    /// `ZMSG|v4|<conv>|INIT|<address>|<message>` (:235-238). No size check (also used by the relay path).
    public static func createV4InitMessage(convId: String, senderAddress: String, message: String) throws -> String {
        try validateConvId(convId)
        return "\(P.v4)\(convId)|\(M.initial)\(senderAddress)|\(message)"
    }

    /// `ZMSG|v4|<conv>|<hash16>|<message>` (:248-252).
    public static func createV4ReplyMessage(convId: String, senderAddress: String, message: String) throws -> String {
        try validateConvId(convId)
        let hash = generateAddressHash(senderAddress)
        return "\(P.v4)\(convId)|\(hash)|\(message)"
    }

    /// `ZMSG|v4|<conv>|KEX|<hash16>|<payload>` (:306-310).
    public static func createV4KEXMessage(convId: String, senderAddress: String, kexPayload: String) throws -> String {
        try validateConvId(convId)
        let hash = generateAddressHash(senderAddress)
        return "\(P.v4)\(convId)|\(M.kex)\(hash)|\(kexPayload)"
    }

    /// `ZMSG|v4|<conv>|KEXACK|<hash16>|<payload>` (:319-323).
    public static func createV4KEXAckMessage(convId: String, senderAddress: String,
                                             kexAckPayload: String) throws -> String {
        try validateConvId(convId)
        let hash = generateAddressHash(senderAddress)
        return "\(P.v4)\(convId)|\(M.kexAck)\(hash)|\(kexAckPayload)"
    }

    /// `ZMSG|v4|<conv>|ADDR|<oldHash16>|<newAddress>|<signature>` (:449-458).
    public static func createV4ADDRMessage(convId: String, oldSenderAddress: String, newAddress: String,
                                           signature: String) throws -> String {
        try validateConvId(convId)
        let oldHash = generateAddressHash(oldSenderAddress)
        return "\(P.v4)\(convId)|\(M.addr)\(oldHash)|\(newAddress)|\(signature)"
    }

    // MARK: - Chunking (:73-124, :207-222, :509-599)

    /// UTF-8 size of one code point.
    static func utf8Width(_ s: Unicode.Scalar) -> Int {
        let v = s.value
        if v < 0x80 { return 1 }
        if v < 0x800 { return 2 }
        if v < 0x10000 { return 3 }
        return 4
    }

    /// packChunks (:104-119) with substringByBytes (:73-89): whole code points measured in UTF-8 bytes; the first part
    /// gets `firstChunkSize`, later parts CONTINUATION; a code point that does not fit an empty part is forced
    /// through. An empty message is one empty part.
    static func packChunks(_ message: String, firstChunkSize: Int) -> [String] {
        let scalars = Array(message.unicodeScalars)
        if scalars.isEmpty { return [""] }
        var parts: [String] = []
        var pos = 0
        while pos < scalars.count {
            let budget = parts.isEmpty ? firstChunkSize : ZMSGConstants.ChunkSizes.continuation
            var end = pos
            var used = 0
            while end < scalars.count {
                let w = utf8Width(scalars[end])
                if used + w > budget { break }
                used += w
                end += 1
            }
            if end == pos { end = pos + 1 }
            parts.append(String(String.UnicodeScalarView(scalars[pos..<end])))
            pos = end
        }
        return parts
    }

    /// Text budget of the first v4 INIT chunk: 512 - (9 + 6 + 1 + 8 + 1 + 5 + 1) - UTF-8 bytes of the address,
    /// at least 1 (:207-222). The header is reserved at its widest, "1/1000".
    public static func v4InitFirstChunkBudget(senderAddress: String) -> Int {
        let maxHeaderWidth = "1/".utf16.count + String(ZMSGConstants.maxChunks).utf16.count
        let fixedOverhead = P.v4c.utf16.count + maxHeaderWidth + 1 + ZMSGConstants.convIdLength + 1
            + M.initial.utf16.count + 1
        return max(ZMSGConstants.maxMemoSize - fixedOverhead - senderAddress.utf8.count, 1)
    }

    /// :509-544. One part is the single INIT format, refused over 512 bytes; otherwise
    /// `ZMSG|v4c|1/N|<conv>|INIT|<addr>|<part>` then `ZMSG|v4c|M/N|CONT|<part>`.
    public static func createChunkedV4InitMessages(convId: String, senderAddress: String,
                                                   message: String) throws -> [String] {
        try validateConvId(convId)
        let parts = packChunks(message, firstChunkSize: v4InitFirstChunkBudget(senderAddress: senderAddress))
        let total = parts.count
        guard total <= ZMSGConstants.maxChunks else { throw ZMSGError.tooManyChunks(count: total) }
        if total == 1 {
            let single = try createV4InitMessage(convId: convId, senderAddress: senderAddress, message: message)
            let size = single.utf8.count
            guard size <= ZMSGConstants.maxMemoSize else { throw ZMSGError.memoTooLong(bytes: size) }
            return [single]
        }
        var chunks: [String] = []
        chunks.reserveCapacity(total)
        for (offset, part) in parts.enumerated() {
            let i = offset + 1
            if i == 1 {
                chunks.append("\(P.v4c)\(i)/\(total)|\(convId)|\(M.initial)\(senderAddress)|\(part)")
            } else {
                chunks.append("\(P.v4c)\(i)/\(total)|\(M.cont)\(part)")
            }
        }
        return chunks
    }

    /// :553-577. One part is the single reply format; otherwise `ZMSG|v4c|1/N|<conv>|<hash16>|<part>` then CONT.
    public static func createChunkedV4ReplyMessages(convId: String, senderAddress: String,
                                                    message: String) throws -> [String] {
        try validateConvId(convId)
        let parts = packChunks(message, firstChunkSize: ZMSGConstants.ChunkSizes.v4ReplyFirst)
        let total = parts.count
        guard total <= ZMSGConstants.maxChunks else { throw ZMSGError.tooManyChunks(count: total) }
        if total == 1 {
            return [try createV4ReplyMessage(convId: convId, senderAddress: senderAddress, message: message)]
        }
        let hash = generateAddressHash(senderAddress)
        var chunks: [String] = []
        chunks.reserveCapacity(total)
        for (offset, part) in parts.enumerated() {
            let i = offset + 1
            if i == 1 {
                chunks.append("\(P.v4c)\(i)/\(total)|\(convId)|\(hash)|\(part)")
            } else {
                chunks.append("\(P.v4c)\(i)/\(total)|\(M.cont)\(part)")
            }
        }
        return chunks
    }

    /// :590-599: the count packChunks gives. INIT without an address falls back to the fixed 330.
    public static func calculateV4ChunkCount(message: String, isInitMessage: Bool, senderAddress: String? = nil) -> Int {
        let firstChunkSize: Int
        if isInitMessage {
            firstChunkSize = senderAddress.map { v4InitFirstChunkBudget(senderAddress: $0) }
                ?? ZMSGConstants.ChunkSizes.v4Init
        } else {
            firstChunkSize = ZMSGConstants.ChunkSizes.v4ReplyFirst
        }
        return packChunks(message, firstChunkSize: firstChunkSize).count
    }

    // MARK: - Lightweight single-memo parsers (:261-502)

    static func parseV4InitUnits(_ u: UTF16Units) -> (address: UTF16Units, message: UTF16Units)? {
        guard KS.startsWith(u, Wire.v4) else { return nil }
        let content = KS.removePrefix(u, Wire.v4)
        let firstPipe = KS.indexOf(content, KS.pipe)
        guard firstPipe == ZMSGConstants.convIdLength else { return nil }
        let convId = KS.substring(content, 0, firstPipe)
        guard convId.allSatisfy({ KS.isConvIdChar($0) }) else { return nil }
        let remaining = KS.substring(content, firstPipe + 1)
        guard KS.startsWith(remaining, Wire.initial) else { return nil }
        let afterInit = KS.removePrefix(remaining, Wire.initial)
        let sep = KS.indexOf(afterInit, KS.pipe)
        guard sep != -1 else { return nil }
        let address = KS.substring(afterInit, 0, sep)
        let message = KS.substring(afterInit, sep + 1)
        guard !KS.isBlank(address) else { return nil }
        return (address, message)
    }

    /// (address, message) of a well-formed single v4 INIT, else nil (:261-277). Touches no cache.
    public static func parseV4Init(_ memo: String) -> (address: String, message: String)? {
        guard let r = parseV4InitUnits(KS.units(memo)) else { return nil }
        return (KS.string(r.address), KS.string(r.message))
    }

    /// The conv id of a memo parseV4Init accepts, else nil (:283-284).
    public static func parseV4InitConvId(_ memo: String) -> String? {
        let u = KS.units(memo)
        guard parseV4InitUnits(u) != nil else { return nil }
        return KS.string(KS.substring(KS.removePrefix(u, Wire.v4), 0, ZMSGConstants.convIdLength))
    }

    /// `ZMSG|v4|` + 8 units + '|' + marker (:328-347, :463-470); the conv id charset is not checked here.
    static func hasV4Marker(_ u: UTF16Units, _ marker: UTF16Units) -> Bool {
        guard KS.startsWith(u, Wire.v4) else { return false }
        let a = KS.removePrefix(u, Wire.v4)
        let n = ZMSGConstants.convIdLength
        return a.count > n + 1 && a[n] == KS.pipe && KS.startsWith(KS.substring(a, n + 1), marker)
    }

    public static func isKEXMessage(_ memo: String) -> Bool { hasV4Marker(KS.units(memo), Wire.kex) }

    public static func isKEXAckMessage(_ memo: String) -> Bool { hasV4Marker(KS.units(memo), Wire.kexAck) }

    public static func isADDRMessage(_ memo: String) -> Bool { hasV4Marker(KS.units(memo), Wire.addr) }

    /// `split("|", limit = 4)` after the prefix: [conv, KEX, hash, payload] (:383-403).
    public static func parseKEXMessage(_ memo: String) -> KexEnvelope? {
        let u = KS.units(memo)
        guard hasV4Marker(u, Wire.kex) else { return nil }
        return envelope(u)
    }

    /// As parseKEXMessage for KEXACK (:411-429).
    public static func parseKEXAckMessage(_ memo: String) -> KexEnvelope? {
        let u = KS.units(memo)
        guard hasV4Marker(u, Wire.kexAck) else { return nil }
        return envelope(u)
    }

    private static func envelope(_ u: UTF16Units) -> KexEnvelope? {
        let parts = KS.split(KS.removePrefix(u, Wire.v4), KS.pipe, limit: 4)
        guard parts.count >= 4 else { return nil }
        return KexEnvelope(conversationId: KS.string(parts[0]), payload: KS.string(parts[3]))
    }

    /// `split("|", limit = 5)` after the prefix: [conv, ADDR, oldHash, newAddress, signature] (:478-502).
    public static func parseADDRMessage(_ memo: String) -> ParsedADDRMessage? {
        let u = KS.units(memo)
        guard hasV4Marker(u, Wire.addr) else { return nil }
        let parts = KS.split(KS.removePrefix(u, Wire.v4), KS.pipe, limit: 5)
        guard parts.count >= 5 else { return nil }
        return ParsedADDRMessage(conversationId: KS.string(parts[0]), oldSenderHash: KS.string(parts[2]),
                                 newAddress: KS.string(parts[3]), signature: KS.string(parts[4]))
    }

    /// `ZMSG|v3c|` or `ZMSG|v4c|` (:1539).
    public static func isChunkedMemo(_ memo: String) -> Bool {
        let u = KS.units(memo)
        return KS.startsWith(u, Wire.v3c) || KS.startsWith(u, Wire.v4c)
    }

    /// "ZMSG|", "ZMSG:" or ZREACT| ZRCPT| ZSTAT| ZTL| ZUNLOCK| ZREQ| ZFILE| (:778-788).
    public static func isRecognizedZmsgEnvelope(_ memo: String) -> Bool {
        isRecognized(KS.units(memo))
    }

    static func isRecognized(_ u: UTF16Units) -> Bool {
        Wire.recognised.contains { KS.startsWith(u, $0) }
    }

    // MARK: - One transaction split by memo kind (:349-375, ZC-1279)

    private enum MemoKind { case kex, kexAck, zboot, other }

    private static func memoKind(_ memo: String) -> MemoKind {
        let text = KS.trim(KS.units(memo))
        if hasV4Marker(text, Wire.kex) { return .kex }
        if hasV4Marker(text, Wire.kexAck) { return .kexAck }
        if KS.startsWith(text, Wire.zbootAny) { return .zboot }
        return .other
    }

    /// Every memo one kind: one unit equal to the input. Mixed: one unit per KEX, then KEXACK, then ZBOOT memo, then
    /// one unit with the other memos in input order, dropped when all of them are blank.
    public static func splitMemosByKind(_ memos: [String]) -> [[String]] {
        var kex: [String] = []
        var kexAck: [String] = []
        var zboot: [String] = []
        var other: [String] = []
        for memo in memos {
            switch memoKind(memo) {
            case .kex: kex.append(memo)
            case .kexAck: kexAck.append(memo)
            case .zboot: zboot.append(memo)
            case .other: other.append(memo)
            }
        }
        let kinds = [kex, kexAck, zboot, other].filter { !$0.isEmpty }.count
        if kinds <= 1 { return [memos] }
        var units: [[String]] = (kex + kexAck + zboot).map { [$0] }
        if other.contains(where: { !KS.isBlank(KS.units($0)) }) { units.append(other) }
        return units
    }
}
