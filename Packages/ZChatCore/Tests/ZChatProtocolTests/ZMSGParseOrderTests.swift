// PAR-0002: parseMemo dispatch order, legacy formats, the recognised-envelope rule and the per-kind split of one
// transaction, as Android 2.13.0. Census CENSUS1_WIRE_v2.13.0.md §1.3, §1.5, §1.6. Android lines:
// UI/screen/chat/model/ZMSGProtocol.kt at 479a084d3 (parseMemo :674-767, isRecognizedZmsgEnvelope :778-788,
// parseGroupMessage :795-810, parseV4Message :819-914, parseRefMessage :922-974, parseV3InitMessage :981-1010,
// parseV3ReplyMessage :1012-1050, parseV2Message :1052-1081, parseReplyMemo :1679-1732, splitMemosByKind :349-375)
// and UI/screen/chat/model/ZBootMessage.kt :56-127.
// Real code order (census §1.6): GROUP, ZBOOT (second; the spec's "Parsing Priority" omits it: DRIFT), ZMSG|v4|,
// ZMSG|v3|INIT|, ZMSG|v3|REF|, ZMSG|v3|RPL|, ZMSG|v3|, ZMSG|v2|, recognised envelope -> VERSION_MISMATCH, else PLAIN.
// Contract: see ZMSGContractTests.swift.

import Testing
@testable import ZChatProtocol

private let h = "ba7816bf8f01cfea"          // generateAddressHash("abc"), FIPS 180-2 vector
private let hex64 = rep("a", 64)

/// ZBOOT memos that ZBootMessage.parse rejects (ZBootMessage.kt:71-127).
private let zbootRejects: [String] = [
    "ZBOOT|v1|ABCD1234|x",                                                   // v1 rejected by parse
    "ZBOOT|",
    "ZBOOT|v3|ABCD1234|\(rep("A", 64))|wss://r.example|0|c2ln",              // pubkey not lowercase
    "ZBOOT|v3|ABCD1234|\(rep("a", 63))|wss://r.example|0|c2ln",              // pubkey 63
    "ZBOOT|v3|ABCD1234|\(hex64)|ws://r.example|0|c2ln",                      // not wss
    "ZBOOT|v3|ABCD1234|\(hex64)|wss://\(rep("r", 75))|0|c2ln",               // relay 81 chars
    "ZBOOT|v3|ABCD1234|\(hex64)|wss://r.example|0|",                         // empty sig
    "ZBOOT|v3|ABCD1234|\(hex64)|wss://r.example|0|\(rep("s", 201))",         // sig 201
    "ZBOOT|v3|ABCD1234|\(hex64)|wss://r.example|-1|c2ln",                    // negative epoch
    "ZBOOT|v3|ABCD1234|\(hex64)|wss://r.example|x|c2ln",                     // epoch not a number
    "ZBOOT|v3|ABCD123|\(hex64)|wss://r.example|0|c2ln",                      // conv 7
    "ZBOOT|v3|ABCD1234|\(hex64)|wss://r.example|0",                          // 4 parts
    "ZBOOT|v2|ABCD1234|\(hex64)|wss://r.example",                            // v2, 3 parts
]

@Suite("ZMSG parseMemo: GROUP first")
struct ZMSGParseGroupTests {
    // ZMSGProtocol.kt:678, :795-810; ZMSGGroupProtocol.kt:98-123 (split(":", limit = 3) after the prefix);
    // GroupModels.kt:40-62. provisional (typed from code)
    @Test func groupEnvelopeYieldsTypeIdAndRawPayload() {
        let r = parseOne("ZMSG:3.0:GROUP:GM:g123:{\"seq\":1,\"ct\":\"a:b\"}")
        #expect(r == ParsedMessage(
            senderAddress: nil, senderHash: nil, message: "{\"seq\":1,\"ct\":\"a:b\"}", isUnknownSender: false,
            reason: nil, messageType: .group, groupId: "g123", groupMessageType: .groupMsg))
    }

    // GroupModels.kt:40-57: every wire code maps; an unknown code stays a GROUP with no type. provisional (typed from
    // code)
    @Test func groupCodes() {
        let codes: [(String, GroupMessageType)] = [
            ("GC", .groupCreate), ("GI", .groupInvite), ("GA", .groupAccept), ("GL", .groupLeave),
            ("GK", .groupKick), ("GM", .groupMsg), ("GY", .groupKey), ("GF", .groupInfo),
            ("GR", .groupKeyRequest), ("GP", .groupMember), ("GQ", .groupRosterQuery),
        ]
        for (code, type) in codes {
            #expect(parseOne("ZMSG:3.0:GROUP:\(code):g1:{}").groupMessageType == type)
            #expect(GroupMessageType(rawValue: code) == type)
        }
        let unknown = parseOne("ZMSG:3.0:GROUP:ZZ:g1:p")
        #expect(unknown.messageType == .group)
        #expect(unknown.groupMessageType == nil)
        #expect(unknown.groupId == "g1")
        #expect(unknown.message == "p")
    }

    // ZMSGGroupProtocol.kt:108-123, ZMSGProtocol.kt:803: a missing id or payload is nil and the message is the memo.
    // provisional (typed from code)
    @Test func truncatedGroupEnvelopes() {
        let noId = parseOne("ZMSG:3.0:GROUP:GM")
        #expect(noId.messageType == .group)
        #expect(noId.groupId == nil)
        #expect(bytes(noId.message) == bytes("ZMSG:3.0:GROUP:GM"))
        let noPayload = parseOne("ZMSG:3.0:GROUP:GM:g1")
        #expect(noPayload.groupId == "g1")
        #expect(bytes(noPayload.message) == bytes("ZMSG:3.0:GROUP:GM:g1"))
    }
}

@Suite("ZMSG parseMemo: ZBOOT second")
struct ZMSGParseZBootTests {
    // Android test RetestGap08ZMSGProtocolZBootRoutingTest.parseMemo_routesWellFormedZBoot_andSurfacesConvId (:47-64).
    @Test func wellFormedZBootSurfacesItsConvId() {
        let r = parseOne(Fixture.wellFormedBoot)
        #expect(r == ParsedMessage(
            senderAddress: nil, senderHash: nil, message: Fixture.wellFormedBoot, isUnknownSender: true, reason: nil,
            conversationId: Fixture.bootConvId))
    }

    // ZMSGProtocol.kt:687-697 + ZBootMessage.kt:61: ANY "ZBOOT|" memo takes the ZBOOT branch (consumed, never shown
    // raw): reason nil, NOT NOT_ZMSG_FORMAT, even when ZBootMessage.parse rejects it (then convId is nil).
    // provisional (typed from code)
    @Test(arguments: zbootRejects)
    func anyZBootPrefixIsConsumedEvenWhenItsBodyIsRejected(memo: String) {
        let r = parseOne(memo)
        #expect(r == ParsedMessage(
            senderAddress: nil, senderHash: nil, message: memo, isUnknownSender: true, reason: nil,
            conversationId: nil))
    }

    // ZBootMessage.kt:71-127: v2 (no epoch), v3 and v4 shapes all surface the conv id; extra fields are ignored
    // (split with no limit, fields [0..4] read); relay of exactly 80 chars and sig of 200 are accepted.
    // provisional (typed from code)
    @Test func zbootVersionsAndBoundaries() {
        #expect(parseOne("ZBOOT|v2|ABCD1234|\(hex64)|wss://r.example|c2ln").conversationId == "ABCD1234")
        #expect(parseOne("ZBOOT|v4|ABCD1234|\(hex64)|wss://r.example|7|\(rep("ab", 64))").conversationId == "ABCD1234")
        #expect(parseOne("ZBOOT|v3|ABCD1234|\(hex64)|wss://r.example|0|c2ln|extra").conversationId == "ABCD1234")
        #expect(parseOne("ZBOOT|v3|ABCD1234|\(hex64)|wss://\(rep("r", 74))|0|c2ln").conversationId == "ABCD1234")
        #expect(parseOne("ZBOOT|v3|ABCD1234|\(hex64)|wss://r.example|0|\(rep("s", 200))").conversationId == "ABCD1234")
    }

    // ZBootMessage.kt:122 checks only the LENGTH of the conv id, as a Kotlin String: UTF-16 units, and no charset.
    // "ABCDEF" + U+1F600 is 8 UTF-16 units (7 scalars, 7 Characters) and is accepted; "ABCDEFG" + U+1F600 is 9 and
    // is not; lowercase passes. provisional (typed from code)
    @Test func zbootConvIdLengthIsUtf16AndCharsetIsUnchecked() {
        let tail = "|\(hex64)|wss://r.example|0|c2ln"
        let eight = parseOne("ZBOOT|v3|ABCDEF\u{1F600}" + tail)
        #expect(eight.conversationId.map(bytes) == bytes("ABCDEF\u{1F600}"))
        #expect(parseOne("ZBOOT|v3|ABCDEFG\u{1F600}" + tail).conversationId == nil)
        #expect(parseOne("ZBOOT|v3|abcd1234" + tail).conversationId == "abcd1234")
    }

    // The relay limit (ZBootMessage.kt:124) is 80 UTF-16 units: "wss://" + 72 ASCII + U+1F600 is 80 units (accepted),
    // + 73 ASCII is 81 (rejected). provisional (typed from code)
    @Test func zbootRelayLengthIsUtf16() {
        let ok = "ZBOOT|v3|ABCD1234|\(hex64)|wss://\(rep("r", 72))\u{1F600}|0|c2ln"
        let over = "ZBOOT|v3|ABCD1234|\(hex64)|wss://\(rep("r", 73))\u{1F600}|0|c2ln"
        #expect(parseOne(ok).conversationId == "ABCD1234")
        #expect(parseOne(over).conversationId == nil)
    }
}

@Suite("ZMSG parseMemo: v4")
struct ZMSGParseV4Tests {
    // ZMSGProtocol.kt:849-878: INIT gives address, hash, message (later pipes kept) and caches hash -> address.
    // provisional (typed from code)
    @Test func initIsParsedAndCached() {
        var cache = TestAddressCache()
        let r = parseCaching("ZMSG|v4|CONV0001|INIT|u1addr|hello|x", &cache)
        let hash = ZMSGProtocol.generateAddressHash("u1addr")
        #expect(r == ParsedMessage(
            senderAddress: "u1addr", senderHash: hash, message: "hello|x", isUnknownSender: false, reason: nil,
            conversationId: "CONV0001", messageType: .regular))
        #expect(cache.getAddress(hash: hash) == "u1addr")
        let reply = parseCaching("ZMSG|v4|CONV0001|\(hash)|hi", &cache)
        #expect(reply.senderAddress == "u1addr")
    }

    // ZMSGProtocol.kt:880-900: 16 or 12 lowercase-hex hash; address from the cache, may be nil, never "unknown".
    // provisional (typed from code)
    @Test func replyWithHash() {
        #expect(parseOne("ZMSG|v4|CONV0001|\(h)|hi") == ParsedMessage(
            senderAddress: nil, senderHash: h, message: "hi", isUnknownSender: false, reason: nil,
            conversationId: "CONV0001"))
        #expect(parseOne("ZMSG|v4|CONV0001|ba7816bf8f01|hi").senderHash == "ba7816bf8f01")
        var seeded = TestAddressCache()
        seeded.cacheAddress(hash: h, address: "abc")
        #expect(parseOne("ZMSG|v4|CONV0001|\(h)|hi", cache: seeded).senderAddress == "abc")
    }

    // ZMSGProtocol.kt:901-911: anything else after the conv id is the legacy hashless reply, whole rest as text:
    // uppercase hex, 13 hex, no pipe at all, and a KEX memo (QUIRK: parseMemo does not route KEX; callers test
    // isKEXMessage first). provisional (typed from code)
    @Test(arguments: [
        ("ZMSG|v4|CONV0001|hello", "hello"),
        ("ZMSG|v4|CONV0001|BA7816BF8F01CFEA|hi", "BA7816BF8F01CFEA|hi"),
        ("ZMSG|v4|CONV0001|ba7816bf8f01c|hi", "ba7816bf8f01c|hi"),
        ("ZMSG|v4|CONV0001|KEX|\(h)|KEX:p:s", "KEX|\(h)|KEX:p:s"),
        ("ZMSG|v4|CONV0001|", ""),
    ])
    func hashlessLegacyReply(memo: String, text: String) {
        let r = parseOne(memo)
        #expect(r == ParsedMessage(
            senderAddress: nil, senderHash: nil, message: text, isUnknownSender: false, reason: nil,
            conversationId: "CONV0001"))
        #expect(bytes(r.message) == bytes(text))
    }

    // ZMSGProtocol.kt:822-861: conv id must end at UTF-16 offset 8 and be CONV_ID_CHARS; INIT needs a separator.
    // Otherwise MALFORMED_MESSAGE with the raw memo. provisional (typed from code)
    @Test(arguments: [
        "ZMSG|v4|CONV001|hello",
        "ZMSG|v4|CONV00011|hello",
        "ZMSG|v4|conv0001|hello",
        "ZMSG|v4|CONV0001",
        "ZMSG|v4|",
        "ZMSG|v4|CONV0001|INIT|nosep",
        "ZMSG|v4|CONV\u{C9}001|hello",
    ])
    func malformedV4(memo: String) {
        #expect(parseOne(memo) == ParsedMessage(
            senderAddress: nil, senderHash: nil, message: memo, isUnknownSender: true, reason: .malformedMessage))
    }

    // Separator search is per code point (Kotlin indexOf over UTF-16, ZMSGProtocol.kt:852, :882): a combining mark
    // right after '|' must not hide the '|' (in Swift "|\u{301}" is one Character). provisional (typed from code)
    @Test func combiningMarkAfterAHashSeparator() {
        let r = parseOne("ZMSG|v4|CONV0001|\(h)|\u{301}x")
        #expect(r.senderHash == h)
        #expect(bytes(r.message) == [0xCC, 0x81, 0x78])
        let i = parseOne("ZMSG|v4|CONV0001|INIT|u1addr|\u{301}")
        #expect(i.senderAddress == "u1addr")
        #expect(bytes(i.message) == [0xCC, 0x81])
    }
}

@Suite("ZMSG parseMemo: legacy v3 and v2 (parse only)")
struct ZMSGParseLegacyTests {
    let u1hash = ZMSGProtocol.generateAddressHash("u1addr")

    // ZMSGProtocol.kt:704, :981-1010. provisional (typed from code)
    @Test func v3Init() {
        #expect(parseOne("ZMSG|v3|INIT|u1addr|m|x") == ParsedMessage(
            senderAddress: "u1addr", senderHash: u1hash, message: "m|x", isUnknownSender: false, reason: nil))
        #expect(parseOne("ZMSG|v3|INIT|nosep").reason == .malformedMessage)
    }

    // ZMSGProtocol.kt:709-718, :922-974: REF is checked before the generic v3 hash form. provisional (typed from code)
    @Test func v3Ref() {
        #expect(parseOne("ZMSG|v3|REF|tx1|abcdef012345|m") == ParsedMessage(
            senderAddress: nil, senderHash: "abcdef012345", message: "m", isUnknownSender: true,
            reason: .hashNotInCache, replyToTxId: "tx1"))
        #expect(parseOne("ZMSG|v3|REF|tx1|INIT|u1addr|m") == ParsedMessage(
            senderAddress: "u1addr", senderHash: u1hash, message: "m", isUnknownSender: false, reason: nil,
            replyToTxId: "tx1"))
        for bad in ["ZMSG|v3|REF|tx1", "ZMSG|v3|REF|tx1|nosep", "ZMSG|v3|REF|tx1|INIT|nosep"] {
            #expect(parseOne(bad) == ParsedMessage(
                senderAddress: nil, senderHash: nil, message: bad, isUnknownSender: true, reason: .malformedMessage))
        }
    }

    // ZMSGProtocol.kt:720-729, :1679-1732 (this pins the census's open Q-L1-2 from code):
    // `ZMSG|v3|RPL|<txid>|INIT|<addr>|<msg>` or `ZMSG|v3|RPL|<txid>|<hash>|<msg>`, messageType REPLY.
    // provisional (typed from code)
    @Test func v3Rpl() {
        #expect(parseOne("ZMSG|v3|RPL|tx1|abcdef012345|m") == ParsedMessage(
            senderAddress: nil, senderHash: "abcdef012345", message: "m", isUnknownSender: true,
            reason: .hashNotInCache, replyToTxId: "tx1", messageType: .reply))
        #expect(parseOne("ZMSG|v3|RPL|tx1|INIT|u1addr|m") == ParsedMessage(
            senderAddress: "u1addr", senderHash: u1hash, message: "m", isUnknownSender: false, reason: nil,
            replyToTxId: "tx1", messageType: .reply))
        #expect(parseOne("ZMSG|v3|RPL|tx1") == ParsedMessage(
            senderAddress: nil, senderHash: nil, message: "ZMSG|v3|RPL|tx1", isUnknownSender: true,
            reason: .malformedMessage))
    }

    // ZMSGProtocol.kt:731, :1012-1050: the generic v3 form takes ANY text before the first '|' as the hash.
    // provisional (typed from code)
    @Test func v3Hash() {
        #expect(parseOne("ZMSG|v3|abcdef012345|m") == ParsedMessage(
            senderAddress: nil, senderHash: "abcdef012345", message: "m", isUnknownSender: true,
            reason: .hashNotInCache))
        var seeded = TestAddressCache()
        seeded.cacheAddress(hash: "abcdef012345", address: "u1known")
        #expect(parseOne("ZMSG|v3|abcdef012345|m", cache: seeded) == ParsedMessage(
            senderAddress: "u1known", senderHash: "abcdef012345", message: "m", isUnknownSender: false, reason: nil))
        #expect(parseOne("ZMSG|v3|nosep").reason == .malformedMessage)
    }

    // ZMSGProtocol.kt:736, :1052-1081. provisional (typed from code)
    @Test func v2() {
        #expect(parseOne("ZMSG|v2|u1addr|m|x") == ParsedMessage(
            senderAddress: "u1addr", senderHash: u1hash, message: "m|x", isUnknownSender: false, reason: nil))
        #expect(parseOne("ZMSG|v2|nosep").reason == .malformedMessage)
    }

    // Every INIT-carrying legacy form caches hash -> address (:1001, :944, :1072, :1702). provisional (typed from
    // code)
    @Test func legacyInitFormsCacheTheAddress() {
        for memo in ["ZMSG|v3|INIT|u1addr|m", "ZMSG|v3|REF|t|INIT|u1addr|m", "ZMSG|v3|RPL|t|INIT|u1addr|m",
                     "ZMSG|v2|u1addr|m"] {
            var cache = TestAddressCache()
            _ = parseCaching(memo, &cache)
            #expect(cache.getAddress(hash: u1hash) == "u1addr")
        }
    }

    // GROUP and ZBOOT never touch the cache (ZMSGProtocol.kt:687-697, :795-810). provisional (typed from code)
    @Test func groupAndZBootDoNotTouchTheCache() {
        var cache = TestAddressCache()
        _ = parseCaching("ZMSG:3.0:GROUP:GM:g1:{}", &cache)
        _ = parseCaching(Fixture.wellFormedBoot, &cache)
        #expect(cache.entries.isEmpty)
    }
}

@Suite("ZMSG parseMemo: recognised envelope vs plain")
struct ZMSGParseUnknownTests {
    // Android test RetestGap15ZMSGVersionMismatchReasonTest.parseMemo_recognizedButUndecodableEnvelope_isVersionMismatch_notForeign
    // (:55-68).
    @Test func undecodableZmsgVersionIsVersionMismatch() {
        #expect(ZMSGProtocol.isRecognizedZmsgEnvelope("ZMSG|v1|legacypayload"))
        let r = parseOne("ZMSG|v1|legacypayload")
        #expect(r.reason == .versionMismatch)
        #expect(r.isUnknownSender)
    }

    // Android tests RetestGap15ZMSGVersionMismatchReasonTest.parseMemo_plainForeignMemo_staysNotZmsgFormat (:70-76)
    // and parseMemo_convIdLookalikeText_isNotAnEnvelope_andSurfacesNoConvId (:78-90).
    @Test func foreignTextIsNotZmsgFormat() {
        let plain = parseOne("plain foreign memo")
        #expect(plain.reason == .notZmsgFormat)
        #expect(plain.isUnknownSender)
        #expect(!ZMSGProtocol.isRecognizedZmsgEnvelope("convId=COLDBOOT trust me"))
        let spoof = parseOne("convId=COLDBOOT trust me")
        #expect(spoof.reason == .notZmsgFormat)
        #expect(spoof.conversationId == nil)
    }

    // ZMSGProtocol.kt:743-751, :778-788: any other "ZMSG|" or "ZMSG:" and the special prefixes ZREACT| ZRCPT| ZSTAT|
    // ZTL| ZUNLOCK| ZREQ| ZFILE| are VERSION_MISMATCH. Chunked v4c / v3c memos are NOT "ZMSG|v4|" and reach parseMemo
    // only as VERSION_MISMATCH (they are read by reassembleChunks). provisional (typed from code)
    @Test(arguments: [
        "ZMSG|v1|legacypayload", "ZMSG|v5|x", "ZMSG|v4", "ZMSG|", "ZMSG:2.0:x", "ZMSG:3.0:GROUPX",
        "ZMSG|v4c|1/2|CONV0001|ba7816bf8f01cfea|a", "ZMSG|v3c|1/2|INIT|u1addr|b",
        "ZREACT|tx|e|ba7816bf8f01cfea", "ZRCPT|tx|ba7816bf8f01cfea", "ZSTAT|busy|ba7816bf8f01cfea",
        "ZTL|SCH|1|ba7816bf8f01cfea|m", "ZUNLOCK|PAY|tx|ba7816bf8f01cfea", "ZREQ|1000|ba7816bf8f01cfea|r",
        "ZFILE|h|j|1|https://nostr.download/x|k|b",
    ])
    func recognisedButUndecodedIsVersionMismatch(memo: String) {
        #expect(ZMSGProtocol.isRecognizedZmsgEnvelope(memo))
        #expect(parseOne(memo) == ParsedMessage(
            senderAddress: nil, senderHash: nil, message: memo, isUnknownSender: true, reason: .versionMismatch))
    }

    // QUIRK, ZMSGProtocol.kt:778-788: ZEXP| ZMODE| ZPROF| ZATT| ZREQ_FULFILL| E2E1: and KEX: are NOT in the
    // recogniser, so a bare one is PLAIN (NOT_ZMSG_FORMAT); prefixes are case-sensitive and never trimmed.
    // provisional (typed from code)
    @Test(arguments: [
        "", "plain foreign memo", "ZEXP|v1|60|1|ba7816bf8f01cfea", "ZMODE|v1|OPEN|1|ba7816bf8f01cfea",
        "ZPROF|v1|x|1/1|s|b", "ZATT|v1|h|j|1|0|https://nostr.download/x|k|b", "ZREQ_FULFILL|id",
        "E2E1:00:0000000000000000:AA==", "KEX:pub:sig", "zmsg|v4|CONV0001|hello", " ZMSG|v4|CONV0001|hello",
        "\nZMSG|v4|CONV0001|hello", "ZBOOT", "zboot|v3|x", "ZMSG", "ZMSGv4|x",
    ])
    func unrecognisedIsPlain(memo: String) {
        #expect(!ZMSGProtocol.isRecognizedZmsgEnvelope(memo))
        #expect(parseOne(memo) == ParsedMessage(
            senderAddress: nil, senderHash: nil, message: memo, isUnknownSender: true, reason: .notZmsgFormat))
    }

    // ZMSGProtocol.kt:1539. provisional (typed from code)
    @Test func chunkedMemoRecogniser() {
        #expect(ZMSGProtocol.isChunkedMemo("ZMSG|v4c|1/2|CONT|x"))
        #expect(ZMSGProtocol.isChunkedMemo("ZMSG|v3c|1/2|CONT|x"))
        #expect(!ZMSGProtocol.isChunkedMemo("ZMSG|v4|CONV0001|x"))
        #expect(!ZMSGProtocol.isChunkedMemo(" ZMSG|v4c|1/2|CONT|x"))
    }
}

@Suite("ZMSG one transaction split by memo kind (ZC-1279)")
struct ZMSGSplitByKindTests {
    // Fixtures in the shape of T/screen/chat/viewmodel/ATransactionOfMixedMemoKindsIsReadByKindTest.kt:58-91
    // (CONV "ZMIX0001", TEXT "synthetic words of a first contact"); payloads are placeholders.
    let m = "ZMSG|v4|ZMIX0001|INIT|u1addr|synthetic words of a first contact"
    let m2 = "ZMSG|v4|ZMIX0001|ba7816bf8f01cfea|second"
    let k = "ZMSG|v4|ZMIX0001|KEX|ba7816bf8f01cfea|KEX:pub:sig"
    let k2 = "ZMSG|v4|ZMIX0002|KEX|ba7816bf8f01cfea|KEX:pub2:sig2"
    let a = "ZMSG|v4|ZMIX0001|KEXACK|ba7816bf8f01cfea|KEXACK:pub:sig"
    let b = Fixture.wellFormedBoot

    // ZMSGProtocol.kt:366-368: every memo one kind -> ONE unit equal to the input, byte for byte (blanks kept;
    // two KEX memos are still one kind). Android test ATransactionOfMixedMemoKindsIsReadByKindTest controls (:39-41).
    @Test func oneKindIsOneUnitUnchanged() {
        #expect(ZMSGProtocol.splitMemosByKind([m]) == [[m]])
        #expect(ZMSGProtocol.splitMemosByKind([m, "", m2]) == [[m, "", m2]])
        #expect(ZMSGProtocol.splitMemosByKind([k, k2]) == [[k, k2]])
        #expect(ZMSGProtocol.splitMemosByKind([b]) == [[b]])
        #expect(ZMSGProtocol.splitMemosByKind([]) == [[]])
    }

    // Android test ATransactionOfMixedMemoKindsIsReadByKindTest, the six first-contact orders (:95-115): one unit per
    // handshake memo in the fixed kind order KEX, KEXACK, ZBOOT, then one unit with the rest.
    @Test(arguments: [[0, 1, 2], [1, 0, 2], [2, 1, 0], [0, 2, 1], [1, 2, 0], [2, 0, 1]])
    func firstContactInAnyOutputOrder(order: [Int]) {
        let memos = [m, k, b]
        #expect(ZMSGProtocol.splitMemosByKind(order.map { memos[$0] }) == [[k], [b], [m]])
    }

    // Android test ATransactionOfMixedMemoKindsIsReadByKindTest, answer orders amb/mab/bam (:164-195).
    @Test(arguments: [[0, 1, 2], [1, 0, 2], [2, 0, 1]])
    func answerInAnyOutputOrder(order: [Int]) {
        let memos = [a, m2, b]
        #expect(ZMSGProtocol.splitMemosByKind(order.map { memos[$0] }) == [[a], [b], [m2]])
    }

    // ZMSGProtocol.kt:369-374: kind order KEX, KEXACK, ZBOOT; inside a kind and inside the rest, input order.
    // provisional (typed from code)
    @Test func kindOrderAndInputOrderInsideAKind() {
        #expect(ZMSGProtocol.splitMemosByKind([b, a, m, k]) == [[k], [a], [b], [m]])
        #expect(ZMSGProtocol.splitMemosByKind([m2, k2, m, k]) == [[k2], [k], [m2, m]])
        #expect(ZMSGProtocol.splitMemosByKind([k, m, b, m2]) == [[k], [b], [m, m2]])
    }

    // ZMSGProtocol.kt:373-374: in a mixed transaction a rest made only of blank memos is dropped; a rest with any
    // non-blank memo keeps its blanks. provisional (typed from code)
    @Test func blankRestIsDroppedOnlyWhenAllBlank() {
        #expect(ZMSGProtocol.splitMemosByKind([k, ""]) == [[k]])
        #expect(ZMSGProtocol.splitMemosByKind([k, "", " \n\t"]) == [[k]])
        #expect(ZMSGProtocol.splitMemosByKind([k, "", m]) == [[k], ["", m]])
    }

    // ZMSGProtocol.kt:351-358: the kind is read from the TRIMMED memo, but the unit holds the memo as received; any
    // "ZBOOT|" (even v1) is the ZBOOT kind; chunked memos are "other". provisional (typed from code)
    @Test func kindIsReadFromTheTrimmedMemo() {
        let spacedBoot = "  " + b + "\n"
        let result = ZMSGProtocol.splitMemosByKind([m, spacedBoot])
        #expect(result == [[spacedBoot], [m]])
        #expect(result.first.map { $0.map(bytes) } == [bytes(spacedBoot)])
        #expect(ZMSGProtocol.splitMemosByKind(["ZBOOT|v1|x", m]) == [["ZBOOT|v1|x"], [m]])
        let c1 = "ZMSG|v4c|1/2|ZMIX0001|ba7816bf8f01cfea|a"
        let c2 = "ZMSG|v4c|2/2|CONT|b"
        #expect(ZMSGProtocol.splitMemosByKind([c2, k, c1]) == [[k], [c2, c1]])
    }
}
