// PAR-0002: reassembly of the chunked memos of one transaction, as Android 2.13.0
// (UI/screen/chat/model/ZMSGProtocol.kt :1224-1323 reassembleChunks, :1328-1431 parseChunkInfo (v3c),
// :1440-1534 parseV4ChunkInfo, at 479a084d3).

/// ZMSGProtocol.kt ChunkInfo (after :1740).
struct ChunkInfo {
    var index: Int
    var total: Int
    var isInit: Bool
    var senderInfo: UTF16Units?
    var messagePart: UTF16Units
    var refTxId: UTF16Units? = nil
    var conversationId: UTF16Units? = nil
}

extension ZMSGProtocol {
    /// Keeps the `ZMSG|v3c|` / `ZMSG|v4c|` memos, sorts them by index, requires exactly {1..N} with N read from the
    /// lowest index, and joins the parts with no separator. No chunked memo: exactly one memo goes to parseMemo,
    /// more give nil.
    public static func reassembleChunks<C: ZMSGAddressCache>(_ memos: [String],
                                                             addressCache: inout C) -> ParsedMessage? {
        if memos.isEmpty { return nil }
        let chunked = memos.map { KS.units($0) }.filter { KS.startsWith($0, Wire.v3c) || KS.startsWith($0, Wire.v4c) }
        if chunked.isEmpty {
            return memos.count == 1 ? parseMemo(memos[0], addressCache: &addressCache) : nil
        }

        // Kotlin sortedBy is stable: sort by (index, input position).
        let parsed: [ChunkInfo] = chunked.compactMap { parseChunkInfo($0) }
        let order: [Int] = parsed.indices.sorted { (parsed[$0].index, $0) < (parsed[$1].index, $1) }
        let chunks: [ChunkInfo] = order.map { parsed[$0] }
        guard let first = chunks.first else { return nil }
        let total = first.total
        guard chunks.count == total else { return nil }
        guard Set(chunks.map { $0.index }) == Set(1...total) else { return nil }

        var senderAddress: String? = nil
        var senderHash: String? = nil
        if first.isInit {
            if let info = first.senderInfo {
                let address = KS.string(info)
                let hash = generateAddressHash(address)
                senderAddress = address
                senderHash = hash
                addressCache.cacheAddress(hash: hash, address: address)
            }
        } else if let info = first.senderInfo, first.conversationId == nil {
            // v3 form with a hash.
            let hash = KS.string(info)
            senderHash = hash
            senderAddress = addressCache.getAddress(hash: hash)
        } else {
            // v4: keep a 12/16 lowercase-hex hash for fallback routing; the address resolves via the conv id.
            if let info = first.senderInfo,
               info.count == ZMSGConstants.hashLength || info.count == ZMSGConstants.hashLengthNew,
               info.allSatisfy({ KS.isLowerHexAscii($0) }) {
                senderHash = KS.string(info)
            }
            if let hash = senderHash {
                senderAddress = addressCache.getAddress(hash: hash)
            }
        }

        var message: UTF16Units = []
        for chunk in chunks { message.append(contentsOf: chunk.messagePart) }

        let convId: String? = first.conversationId.map { KS.string($0) }
        let refTxId: String? = first.refTxId.map { KS.string($0) }
        let isUnknown: Bool = (convId != nil && !first.isInit) ? false : (senderAddress == nil)
        var reason: UnknownReason? = nil
        if isUnknown && senderAddress == nil {
            reason = first.isInit ? .malformedMessage : .hashNotInCache
        }
        return ParsedMessage(senderAddress: senderAddress, senderHash: senderHash, message: KS.string(message),
                             isUnknownSender: isUnknown, reason: reason, replyToTxId: refTxId,
                             conversationId: convId)
    }

    /// `i/N|` with 1 <= i <= N <= 1000, Kotlin toIntOrNull on both numbers (:1340-1354, :1451-1459).
    private static func parseChunkHeader(_ content: UTF16Units) -> (index: Int, total: Int, remaining: UTF16Units)? {
        let end = KS.indexOf(content, KS.pipe)
        guard end != -1 else { return nil }
        let chunkPart = KS.substring(content, 0, end)
        let slash = KS.indexOf(chunkPart, KS.slash)
        guard slash != -1 else { return nil }
        guard let index = KS.toIntOrNull(KS.substring(chunkPart, 0, slash)),
              let total = KS.toIntOrNull(KS.substring(chunkPart, slash + 1)) else { return nil }
        guard index >= 1, total >= 1, index <= total, total <= ZMSGConstants.maxChunks else { return nil }
        return (index, total, KS.substring(content, end + 1))
    }

    /// parseChunkInfo (:1328-1431): v4c goes to parseV4ChunkInfo; v3c first chunks are INIT, REF, CONT or hash.
    static func parseChunkInfo(_ u: UTF16Units) -> ChunkInfo? {
        if KS.startsWith(u, Wire.v4c) { return parseV4ChunkInfo(u) }
        guard KS.startsWith(u, Wire.v3c) else { return nil }
        guard let h = parseChunkHeader(KS.removePrefix(u, Wire.v3c)) else { return nil }
        let remaining = h.remaining

        if KS.startsWith(remaining, Wire.initial) {
            let afterInit = KS.removePrefix(remaining, Wire.initial)
            let sep = KS.indexOf(afterInit, KS.pipe)
            guard sep != -1 else { return nil }
            return ChunkInfo(index: h.index, total: h.total, isInit: true,
                             senderInfo: KS.substring(afterInit, 0, sep),
                             messagePart: KS.substring(afterInit, sep + 1))
        }
        if KS.startsWith(remaining, Wire.ref) {
            let afterRef = KS.removePrefix(remaining, Wire.ref)
            let firstPipe = KS.indexOf(afterRef, KS.pipe)
            guard firstPipe != -1 else { return nil }
            let refTxId = KS.substring(afterRef, 0, firstPipe)
            let afterTxId = KS.substring(afterRef, firstPipe + 1)
            if KS.startsWith(afterTxId, Wire.initial) {
                let afterInit = KS.removePrefix(afterTxId, Wire.initial)
                let sep = KS.indexOf(afterInit, KS.pipe)
                guard sep != -1 else { return nil }
                return ChunkInfo(index: h.index, total: h.total, isInit: true,
                                 senderInfo: KS.substring(afterInit, 0, sep),
                                 messagePart: KS.substring(afterInit, sep + 1), refTxId: refTxId)
            }
            let sep = KS.indexOf(afterTxId, KS.pipe)
            guard sep != -1 else { return nil }
            return ChunkInfo(index: h.index, total: h.total, isInit: false,
                             senderInfo: KS.substring(afterTxId, 0, sep),
                             messagePart: KS.substring(afterTxId, sep + 1), refTxId: refTxId)
        }
        if KS.startsWith(remaining, Wire.cont) {
            return ChunkInfo(index: h.index, total: h.total, isInit: false, senderInfo: nil,
                             messagePart: KS.removePrefix(remaining, Wire.cont))
        }
        let sep = KS.indexOf(remaining, KS.pipe)
        guard sep != -1 else { return nil }
        return ChunkInfo(index: h.index, total: h.total, isInit: false,
                         senderInfo: KS.substring(remaining, 0, sep),
                         messagePart: KS.substring(remaining, sep + 1))
    }

    /// parseV4ChunkInfo (:1440-1534): CONT, or a first chunk `<conv8>|` then INIT, a 12/16 lowercase-hex hash, or
    /// the legacy hashless text.
    static func parseV4ChunkInfo(_ u: UTF16Units) -> ChunkInfo? {
        guard let h = parseChunkHeader(KS.removePrefix(u, Wire.v4c)) else { return nil }
        let remaining = h.remaining

        if KS.startsWith(remaining, Wire.cont) {
            return ChunkInfo(index: h.index, total: h.total, isInit: false, senderInfo: nil,
                             messagePart: KS.removePrefix(remaining, Wire.cont))
        }
        let convIdEnd = KS.indexOf(remaining, KS.pipe)
        guard convIdEnd == ZMSGConstants.convIdLength else { return nil }
        let convId = KS.substring(remaining, 0, convIdEnd)
        guard convId.allSatisfy({ KS.isConvIdChar($0) }) else { return nil }
        let afterConvId = KS.substring(remaining, convIdEnd + 1)

        if KS.startsWith(afterConvId, Wire.initial) {
            let afterInit = KS.removePrefix(afterConvId, Wire.initial)
            let sep = KS.indexOf(afterInit, KS.pipe)
            guard sep != -1 else { return nil }
            return ChunkInfo(index: h.index, total: h.total, isInit: true,
                             senderInfo: KS.substring(afterInit, 0, sep),
                             messagePart: KS.substring(afterInit, sep + 1), conversationId: convId)
        }
        let hashSep = KS.indexOf(afterConvId, KS.pipe)
        let hasHashFormat = (hashSep == ZMSGConstants.hashLength || hashSep == ZMSGConstants.hashLengthNew)
            && KS.substring(afterConvId, 0, hashSep).allSatisfy({ KS.isLowerHexAscii($0) })
        if hasHashFormat {
            return ChunkInfo(index: h.index, total: h.total, isInit: false,
                             senderInfo: KS.substring(afterConvId, 0, hashSep),
                             messagePart: KS.substring(afterConvId, hashSep + 1), conversationId: convId)
        }
        return ChunkInfo(index: h.index, total: h.total, isInit: false, senderInfo: nil,
                         messagePart: afterConvId, conversationId: convId)
    }
}
