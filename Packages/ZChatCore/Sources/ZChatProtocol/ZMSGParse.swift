// PAR-0002: parseMemo dispatch and the legacy v3/v2 parsers, as Android 2.13.0
// (UI/screen/chat/model/ZMSGProtocol.kt :674-1081, :1679-1732; ZMSGGroupProtocol.kt:98-123; ZBootMessage.kt:56-127
// at 479a084d3). Code order (census section 1.6): GROUP, ZBOOT, ZMSG|v4|, ZMSG|v3|INIT|, ZMSG|v3|REF|, ZMSG|v3|RPL|,
// ZMSG|v3|, ZMSG|v2|, recognised envelope (VERSION_MISMATCH), else plain (NOT_ZMSG_FORMAT).

extension ZMSGProtocol {
    public static func parseMemo<C: ZMSGAddressCache>(_ memo: String, addressCache: inout C) -> ParsedMessage {
        let u = KS.units(memo)
        if KS.startsWith(u, Wire.group) {
            return parseGroupMessage(memo, u)
        }
        if KS.startsWith(u, Wire.zbootAny) {
            // Any ZBOOT| is consumed (never shown raw); its conv id only when ZBootMessage.parse accepts it.
            return ParsedMessage(senderAddress: nil, senderHash: nil, message: memo, isUnknownSender: true,
                                 reason: nil, conversationId: ZBoot.parseConvId(u))
        }
        if KS.startsWith(u, Wire.v4) {
            return parseV4Message(memo, u, &addressCache)
        }
        if KS.startsWith(u, Wire.v3Init) {
            return parseV3InitMessage(memo, u, &addressCache)
        }
        if KS.startsWith(u, Wire.v3Ref) {
            return parseRefMessage(u, &addressCache) ?? unknown(memo, .malformedMessage)
        }
        if KS.startsWith(u, Wire.v3Rpl) {
            return parseReplyMemo(u, &addressCache) ?? unknown(memo, .malformedMessage)
        }
        if KS.startsWith(u, Wire.v3) {
            return parseV3ReplyMessage(memo, u, &addressCache)
        }
        if KS.startsWith(u, Wire.v2) {
            return parseV2Message(memo, u, &addressCache)
        }
        if isRecognized(u) {
            return unknown(memo, .versionMismatch)
        }
        return unknown(memo, .notZmsgFormat)
    }

    static func unknown(_ memo: String, _ reason: UnknownReason) -> ParsedMessage {
        ParsedMessage(senderAddress: nil, senderHash: nil, message: memo, isUnknownSender: true, reason: reason)
    }

    /// `ZMSG:3.0:GROUP:<type>:<groupId>:<payload>`, split(":", limit = 3) after the prefix (:795-810).
    static func parseGroupMessage(_ memo: String, _ u: UTF16Units) -> ParsedMessage {
        let parts = KS.split(KS.removePrefix(u, Wire.group), KS.colon, limit: 3)
        let type = GroupMessageType.fromCode(parts[0])
        let groupId: String? = parts.count >= 2 ? KS.string(parts[1]) : nil
        let payload: String? = parts.count >= 3 ? KS.string(parts[2]) : nil
        return ParsedMessage(senderAddress: nil, senderHash: nil, message: payload ?? memo, isUnknownSender: false,
                             reason: nil, messageType: .group, groupId: groupId, groupMessageType: type)
    }

    /// :819-914.
    static func parseV4Message<C: ZMSGAddressCache>(_ memo: String, _ u: UTF16Units,
                                                    _ cache: inout C) -> ParsedMessage {
        let content = KS.removePrefix(u, Wire.v4)
        let firstPipe = KS.indexOf(content, KS.pipe)
        guard firstPipe == ZMSGConstants.convIdLength else { return unknown(memo, .malformedMessage) }
        let convIdUnits = KS.substring(content, 0, firstPipe)
        guard convIdUnits.allSatisfy({ KS.isConvIdChar($0) }) else { return unknown(memo, .malformedMessage) }
        let convId = KS.string(convIdUnits)
        let remaining = KS.substring(content, firstPipe + 1)

        if KS.startsWith(remaining, Wire.initial) {
            let afterInit = KS.removePrefix(remaining, Wire.initial)
            let sep = KS.indexOf(afterInit, KS.pipe)
            guard sep != -1 else { return unknown(memo, .malformedMessage) }
            let address = KS.string(KS.substring(afterInit, 0, sep))
            let message = KS.string(KS.substring(afterInit, sep + 1))
            let hash = generateAddressHash(address)
            cache.cacheAddress(hash: hash, address: address)
            return ParsedMessage(senderAddress: address, senderHash: hash, message: message, isUnknownSender: false,
                                 reason: nil, conversationId: convId, messageType: .regular)
        }

        let hashSep = KS.indexOf(remaining, KS.pipe)
        let hasHashFormat = (hashSep == ZMSGConstants.hashLength || hashSep == ZMSGConstants.hashLengthNew)
            && KS.substring(remaining, 0, hashSep).allSatisfy({ KS.isLowerHexAscii($0) })
        if hasHashFormat {
            let hash = KS.string(KS.substring(remaining, 0, hashSep))
            let message = KS.string(KS.substring(remaining, hashSep + 1))
            return ParsedMessage(senderAddress: cache.getAddress(hash: hash), senderHash: hash, message: message,
                                 isUnknownSender: false, reason: nil, conversationId: convId, messageType: .regular)
        }
        // Legacy hashless reply: the whole rest is the text.
        return ParsedMessage(senderAddress: nil, senderHash: nil, message: KS.string(remaining), isUnknownSender: false,
                             reason: nil, conversationId: convId, messageType: .regular)
    }

    /// `ZMSG|v3|REF|<txid>|<hash>|<msg>` or `ZMSG|v3|REF|<txid>|INIT|<addr>|<msg>` (:922-974).
    static func parseRefMessage<C: ZMSGAddressCache>(_ u: UTF16Units, _ cache: inout C) -> ParsedMessage? {
        parseTxReferenced(KS.removePrefix(u, Wire.v3Ref), .regular, &cache)
    }

    /// `ZMSG|v3|RPL|<txid>|<hash>|<msg>` or `ZMSG|v3|RPL|<txid>|INIT|<addr>|<msg>`, type REPLY (:1679-1732).
    static func parseReplyMemo<C: ZMSGAddressCache>(_ u: UTF16Units, _ cache: inout C) -> ParsedMessage? {
        parseTxReferenced(KS.removePrefix(u, Wire.v3Rpl), .reply, &cache)
    }

    /// The shared body of parseRefMessage and parseReplyMemo (the two Android functions are line for line the same
    /// apart from messageType).
    private static func parseTxReferenced<C: ZMSGAddressCache>(_ content: UTF16Units, _ type: MessageType,
                                                               _ cache: inout C) -> ParsedMessage? {
        let firstPipe = KS.indexOf(content, KS.pipe)
        guard firstPipe != -1 else { return nil }
        let txId = KS.string(KS.substring(content, 0, firstPipe))
        let remaining = KS.substring(content, firstPipe + 1)
        if KS.startsWith(remaining, Wire.initial) {
            let afterInit = KS.removePrefix(remaining, Wire.initial)
            let sep = KS.indexOf(afterInit, KS.pipe)
            guard sep != -1 else { return nil }
            let address = KS.string(KS.substring(afterInit, 0, sep))
            let message = KS.string(KS.substring(afterInit, sep + 1))
            let hash = generateAddressHash(address)
            cache.cacheAddress(hash: hash, address: address)
            return ParsedMessage(senderAddress: address, senderHash: hash, message: message, isUnknownSender: false,
                                 reason: nil, replyToTxId: txId, messageType: type)
        }
        let sep = KS.indexOf(remaining, KS.pipe)
        guard sep != -1 else { return nil }
        let hash = KS.string(KS.substring(remaining, 0, sep))
        let message = KS.string(KS.substring(remaining, sep + 1))
        let address = cache.getAddress(hash: hash)
        return ParsedMessage(senderAddress: address, senderHash: hash, message: message,
                             isUnknownSender: address == nil, reason: address == nil ? .hashNotInCache : nil,
                             replyToTxId: txId, messageType: type)
    }

    /// `ZMSG|v3|INIT|<addr>|<msg>` (:981-1010).
    static func parseV3InitMessage<C: ZMSGAddressCache>(_ memo: String, _ u: UTF16Units,
                                                        _ cache: inout C) -> ParsedMessage {
        parseAddressForm(memo, KS.removePrefix(u, Wire.v3Init), &cache)
    }

    /// `ZMSG|v2|<addr>|<msg>` (:1052-1081).
    static func parseV2Message<C: ZMSGAddressCache>(_ memo: String, _ u: UTF16Units,
                                                    _ cache: inout C) -> ParsedMessage {
        parseAddressForm(memo, KS.removePrefix(u, Wire.v2), &cache)
    }

    private static func parseAddressForm<C: ZMSGAddressCache>(_ memo: String, _ content: UTF16Units,
                                                              _ cache: inout C) -> ParsedMessage {
        let sep = KS.indexOf(content, KS.pipe)
        guard sep != -1 else { return unknown(memo, .malformedMessage) }
        let address = KS.string(KS.substring(content, 0, sep))
        let message = KS.string(KS.substring(content, sep + 1))
        let hash = generateAddressHash(address)
        cache.cacheAddress(hash: hash, address: address)
        return ParsedMessage(senderAddress: address, senderHash: hash, message: message, isUnknownSender: false,
                             reason: nil)
    }

    /// `ZMSG|v3|<hash>|<msg>`: any text before the first '|' is the hash (:1012-1050).
    static func parseV3ReplyMessage<C: ZMSGAddressCache>(_ memo: String, _ u: UTF16Units,
                                                         _ cache: inout C) -> ParsedMessage {
        let content = KS.removePrefix(u, Wire.v3)
        let sep = KS.indexOf(content, KS.pipe)
        guard sep != -1 else { return unknown(memo, .malformedMessage) }
        let hash = KS.string(KS.substring(content, 0, sep))
        let message = KS.string(KS.substring(content, sep + 1))
        if let address = cache.getAddress(hash: hash) {
            return ParsedMessage(senderAddress: address, senderHash: hash, message: message, isUnknownSender: false,
                                 reason: nil)
        }
        return ParsedMessage(senderAddress: nil, senderHash: hash, message: message, isUnknownSender: true,
                             reason: .hashNotInCache)
    }
}

/// ZBootMessage.parse (ZBootMessage.kt:71-127), only as far as parseMemo needs its conv id. Lengths are UTF-16 units.
enum ZBoot {
    static func parseConvId(_ raw: UTF16Units) -> String? {
        if KS.startsWith(raw, Wire.zbootV4) { return parseWithEpoch(KS.removePrefix(raw, Wire.zbootV4)) }
        if KS.startsWith(raw, Wire.zbootV3) { return parseWithEpoch(KS.removePrefix(raw, Wire.zbootV3)) }
        if KS.startsWith(raw, Wire.zbootV2) { return parseV2(KS.removePrefix(raw, Wire.zbootV2)) }
        return nil  // unsigned v1 or anything else
    }

    /// v3 and v4: `<conv>|<pubkey>|<relay>|<epoch>|<sig>` (split with no limit; fields 0 to 4 read).
    private static func parseWithEpoch(_ body: UTF16Units) -> String? {
        let parts = KS.split(body, KS.pipe)
        guard parts.count >= 5 else { return nil }
        guard let epoch = KS.toLongOrNull(parts[3]) else { return nil }
        guard validCommon(parts[0], parts[1], parts[2], parts[4]), epoch >= 0 else { return nil }
        return KS.string(parts[0])
    }

    /// v2: `<conv>|<pubkey>|<relay>|<sig>`.
    private static func parseV2(_ body: UTF16Units) -> String? {
        let parts = KS.split(body, KS.pipe)
        guard parts.count >= 4 else { return nil }
        guard validCommon(parts[0], parts[1], parts[2], parts[3]) else { return nil }
        return KS.string(parts[0])
    }

    /// :121-127: conv id LENGTH 8 (no charset), pubkey ^[0-9a-f]{64}$, relay wss:// and at most 80, sig 1 to 200.
    private static func validCommon(_ convId: UTF16Units, _ pubkey: UTF16Units, _ relay: UTF16Units,
                                    _ sig: UTF16Units) -> Bool {
        if convId.count != ZMSGConstants.convIdLength { return false }
        if pubkey.count != 64 || !pubkey.allSatisfy({ KS.isLowerHexAscii($0) }) { return false }
        if !KS.startsWith(relay, Wire.wss) || relay.count > 80 { return false }
        if sig.isEmpty || sig.count > 200 { return false }
        return true
    }
}
