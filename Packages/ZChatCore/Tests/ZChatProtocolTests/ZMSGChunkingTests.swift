// PAR-0002: byte-aware chunking of v4 messages as Android 2.13.0 does it (packChunks / substringByBytes).
// Census CENSUS1_WIRE_v2.13.0.md §1.4. Android lines: UI/screen/chat/model/ZMSGProtocol.kt at 479a084d3:
//   substringByBytes :73-89 (whole code points, measured in UTF-8 bytes), packChunks :104-119 (a code point that does
//   not fit is forced through), v4InitFirstChunkBudget :207-222, createChunkedV4InitMessages :509-544,
//   createChunkedV4ReplyMessages :553-577, calculateV4ChunkCount :590-599.
// Splitting is per Unicode SCALAR (Kotlin code point), not per Swift Character: a grapheme cluster (ZWJ family,
// e + combining acute) may be split across chunks, exactly as Android splits it.
// Literals marked "(simulated)" were computed offline by a code-point simulation of packChunks; they are provisional
// until the exporter (AGENTS.md rule 4) produces them from Android's production code.

import Testing
@testable import ZChatProtocol

/// The emoji-heavy payload of T/screen/chat/model/ZMSGChunkingEmojiIntegrityTest.kt:66-71, written as scalars
/// (bytes of :69 checked with od: U+1F389, U+1F468 ZWJ U+1F469 ZWJ U+1F467, U+1F680, U+1F600, U+1F1FA U+1F1F3,
/// U+1D11E, U+2070E).
let emojiHeavyMessage: String = (0..<40).map { i in
    "part\(i) \u{1F389}\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{1F680} emoji integrity "
        + "\u{1F600}\u{1F1FA}\u{1F1F3} \u{1D11E}\u{2070E} "
}.joined()

/// T/screen/chat/model/ZMSGChunkingEmojiIntegrityTest.kt:187: the ZWJ family (18 UTF-8 bytes) x 1527.
let desyncPayload = rep("\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}", 1527)

@Suite("ZMSG v4 chunk budgets")
struct ZMSGChunkBudgetTests {
    // ZMSGProtocol.kt:207-222: 512 - (9 + 6 + 1 + 8 + 1 + 5 + 1) - bytes(address), at least 1.
    // provisional (typed from code)
    @Test func initFirstChunkBudgetIsDynamic() {
        #expect(ZMSGProtocol.v4InitFirstChunkBudget(senderAddress: "") == 481)
        #expect(ZMSGProtocol.v4InitFirstChunkBudget(senderAddress: Fixture.sender) == 413)      // 68-byte address
        #expect(ZMSGProtocol.v4InitFirstChunkBudget(senderAddress: Fixture.mainnetUA) == 303)   // 178 bytes
        #expect(ZMSGProtocol.v4InitFirstChunkBudget(senderAddress: Fixture.testnetUA) == 336)   // 145 bytes
        #expect(ZMSGProtocol.v4InitFirstChunkBudget(senderAddress: rep("u", 480)) == 1)
        #expect(ZMSGProtocol.v4InitFirstChunkBudget(senderAddress: rep("u", 600)) == 1)         // coerceAtLeast(1)
    }

    // byteLen(senderAddress) is UTF-8 bytes, not characters (ZMSGProtocol.kt:124, :221). provisional (typed from code)
    @Test func initBudgetCountsAddressBytesNotCharacters() {
        #expect(ZMSGProtocol.v4InitFirstChunkBudget(senderAddress: rep("\u{E9}", 10)) == 461)
    }

    // Android test ZMSGChunkingEmojiIntegrityTest.v4ChunkCount_asciiByteBoundaries_exact (:223-242).
    @Test func chunkCountAsciiBoundaries() throws {
        let initBudget = ZMSGProtocol.v4InitFirstChunkBudget(senderAddress: Fixture.sender)
        let replyBudget = ZMSGConstants.ChunkSizes.v4ReplyFirst
        #expect(ZMSGProtocol.calculateV4ChunkCount(message: rep("a", initBudget), isInitMessage: true,
                                                   senderAddress: Fixture.sender) == 1)
        #expect(ZMSGProtocol.calculateV4ChunkCount(message: rep("a", initBudget + 1), isInitMessage: true,
                                                   senderAddress: Fixture.sender) == 2)
        #expect(ZMSGProtocol.calculateV4ChunkCount(message: rep("a", replyBudget), isInitMessage: false) == 1)
        #expect(ZMSGProtocol.calculateV4ChunkCount(message: rep("a", replyBudget + 1), isInitMessage: false) == 2)

        let twoBytePerChar = rep("\u{E9}", initBudget)  // U+00E9, 2 UTF-8 bytes
        let chunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.convId, senderAddress: Fixture.sender, message: twoBytePerChar)
        #expect(chunks.count == 2)
        #expect(ZMSGProtocol.calculateV4ChunkCount(message: twoBytePerChar, isInitMessage: true,
                                                   senderAddress: Fixture.sender) == chunks.count)
    }

    // ZMSGProtocol.kt:590-599: without an address the INIT estimate falls back to the fixed 330 (:592); a reply ignores
    // the address. provisional (typed from code)
    @Test func initCountWithoutAddressUsesFixedFallback() {
        #expect(ZMSGProtocol.calculateV4ChunkCount(message: rep("a", 330), isInitMessage: true) == 1)
        #expect(ZMSGProtocol.calculateV4ChunkCount(message: rep("a", 331), isInitMessage: true) == 2)
        #expect(ZMSGProtocol.calculateV4ChunkCount(message: rep("a", 463), isInitMessage: false,
                                                   senderAddress: Fixture.mainnetUA) == 2)
        // packChunks("") is one empty part (:105).
        #expect(ZMSGProtocol.calculateV4ChunkCount(message: "", isInitMessage: false) == 1)
    }
}

@Suite("ZMSG v4 chunk layouts")
struct ZMSGChunkLayoutTests {
    // ZMSGProtocol.kt:535-537: first `ZMSG|v4c|1/N|<conv>|INIT|<addr>|<part>`, then `ZMSG|v4c|M/N|CONT|<part>`.
    // 700 'a' with a 178-byte address: budget 303 -> parts 303 + 397. provisional (typed from code)
    @Test func chunkedInitLayoutIsByteExact() throws {
        let chunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.mainnetConvId, senderAddress: Fixture.mainnetUA, message: rep("a", 700))
        #expect(chunks.count == 2)
        #expect(bytes(chunks[0]) == bytes("ZMSG|v4c|1/2|TESTCV01|INIT|" + Fixture.mainnetUA + "|" + rep("a", 303)))
        #expect(bytes(chunks[1]) == bytes("ZMSG|v4c|2/2|CONT|" + rep("a", 397)))
        #expect(byteLen(chunks[0]) == 509)
    }

    // ZMSGProtocol.kt:568-570: first `ZMSG|v4c|1/N|<conv>|<hash16>|<part>`; 1000 'a' -> 462 + 485 + 53.
    // provisional (typed from code)
    @Test func chunkedReplyLayoutIsByteExact() throws {
        let chunks = try ZMSGProtocol.createChunkedV4ReplyMessages(
            convId: "CONV0001", senderAddress: "abc", message: rep("a", 1000))
        #expect(chunks.count == 3)
        #expect(bytes(chunks[0]) == bytes("ZMSG|v4c|1/3|CONV0001|ba7816bf8f01cfea|" + rep("a", 462)))
        #expect(bytes(chunks[1]) == bytes("ZMSG|v4c|2/3|CONT|" + rep("a", 485)))
        #expect(bytes(chunks[2]) == bytes("ZMSG|v4c|3/3|CONT|" + rep("a", 53)))
    }

    // One part means the NON-chunked single format (ZMSGProtocol.kt:518-529, :559-561), including the empty message.
    // provisional (typed from code)
    @Test func onePartUsesTheSingleMemoFormat() throws {
        let reply = try ZMSGProtocol.createChunkedV4ReplyMessages(convId: "CONV0001", senderAddress: "abc", message: "hi")
        #expect(reply.map(bytes) == [bytes("ZMSG|v4|CONV0001|ba7816bf8f01cfea|hi")])
        let emptyReply = try ZMSGProtocol.createChunkedV4ReplyMessages(
            convId: "CONV0001", senderAddress: "abc", message: "")
        #expect(emptyReply.map(bytes) == [bytes("ZMSG|v4|CONV0001|ba7816bf8f01cfea|")])
        let initMemo = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: "CONV0001", senderAddress: "u1addr", message: "")
        #expect(initMemo.map(bytes) == [bytes("ZMSG|v4|CONV0001|INIT|u1addr|")])
    }

    // Android test ZMSGV4InitMainnetOverflowTest.mainnetInit_singleMemoThatFits_isWithinLimit (:108-119).
    @Test func mainnetSingleMemoThatFits() throws {
        var cache = TestAddressCache()
        let message = rep("a", 300)
        let chunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.mainnetConvId, senderAddress: Fixture.mainnetUA, message: message)
        #expect(chunks.count == 1)
        #expect(byteLen(chunks[0]) <= ZMSGConstants.maxMemoSize)
        #expect(byteLen(chunks[0]) == 501)
        let parsed = try reassembled(chunks, &cache)
        #expect(bytes(parsed.message) == bytes(message))
    }

    // Android test ZMSGV4InitMainnetOverflowTest.mainnetInit_singleChunkBoundary_splitsInsteadOfOverflowing (:87-105).
    @Test func mainnetSingleChunkBoundarySplits() throws {
        var cache = TestAddressCache()
        let message = rep("a", 325)
        let chunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.mainnetConvId, senderAddress: Fixture.mainnetUA, message: message)
        #expect(chunks.count > 1)
        for memo in chunks { #expect(byteLen(memo) <= ZMSGConstants.maxMemoSize) }
        let parsed = try reassembled(chunks, &cache)
        #expect(bytes(parsed.message) == bytes(message))
        #expect(parsed.senderAddress == Fixture.mainnetUA)
    }

    // Android tests ZMSGV4InitMainnetOverflowTest.mainnetInit_multiChunk_everyMemoWithinMemoByteLimit (:62-84) and
    // testnetInit_stillWithinLimit_noRegression (:122-140).
    @Test(arguments: [Fixture.mainnetUA, Fixture.testnetUA])
    func multiChunkInitFitsAndRoundTrips(address: String) throws {
        var cache = TestAddressCache()
        let message = rep("a", 700)
        let chunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.mainnetConvId, senderAddress: address, message: message)
        #expect(chunks.count > 1)
        for memo in chunks { #expect(byteLen(memo) <= ZMSGConstants.maxMemoSize) }
        let parsed = try reassembled(chunks, &cache)
        #expect(bytes(parsed.message) == bytes(message))
        #expect(parsed.senderAddress == address)
        #expect(parsed.conversationId == Fixture.mainnetConvId)
    }

    // ZMSGProtocol.kt:524: a one-part INIT whose single memo passes 512 bytes is refused (Kotlin check() throws).
    // 600-byte address + "a" = 8 + 8 + 1 + 5 + 600 + 1 + 1 = 624 bytes. provisional (typed from code)
    @Test func oversizedSingleInitIsRefused() {
        #expect(throws: ZMSGError.memoTooLong(bytes: 624)) {
            try ZMSGProtocol.createChunkedV4InitMessages(convId: "CONV0001", senderAddress: rep("u", 600), message: "a")
        }
    }

    // packChunks :111-114: a budget too small for the next code point forces that one code point through (no spin,
    // no empty part). With a 600-byte address the budget is 1, so a 4-byte emoji is chunk 1 alone. Android's builder
    // does not size-check multi-chunk output (the pre-submit guard elsewhere does), so the over-512 first chunk is
    // returned as is. provisional (typed from code)
    @Test func tooSmallBudgetForcesOneCodePointThrough() throws {
        let address = rep("u", 600)
        let chunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: "CONV0001", senderAddress: address, message: "\u{1F600}x")
        #expect(chunks.count == 2)
        #expect(bytes(chunks[0]) == bytes("ZMSG|v4c|1/2|CONV0001|INIT|" + address + "|\u{1F600}"))
        #expect(bytes(chunks[1]) == bytes("ZMSG|v4c|2/2|CONT|x"))
    }
}

@Suite("ZMSG chunk cap")
struct ZMSGChunkCapTests {
    // ZMSGProtocol.kt:557 (MAX_CHUNKS 1000, :67): 462 + 999 * 485 = 484977 bytes is exactly 1000 chunks; one more byte
    // is 1001 and refused. Every memo still fits 512 at the widest header. provisional (typed from code)
    @Test func replyAtExactlyOneThousandChunks() throws {
        let chunks = try ZMSGProtocol.createChunkedV4ReplyMessages(
            convId: "CONV0001", senderAddress: "abc", message: rep("a", 484_977))
        #expect(chunks.count == 1000)
        #expect(chunks[0].hasPrefix("ZMSG|v4c|1/1000|CONV0001|ba7816bf8f01cfea|"))
        #expect(bytes(chunks[999]) == bytes("ZMSG|v4c|1000/1000|CONT|" + rep("a", 485)))
        #expect(chunks.allSatisfy { byteLen($0) <= ZMSGConstants.maxMemoSize })
        #expect(throws: ZMSGError.tooManyChunks(count: 1001)) {
            try ZMSGProtocol.createChunkedV4ReplyMessages(
                convId: "CONV0001", senderAddress: "abc", message: rep("a", 484_978))
        }
    }

    // ZMSGProtocol.kt:516: same cap on INIT; 68-byte address -> 413 + 999 * 485 = 484928. provisional (typed from code)
    @Test func initCapAtOneThousandChunks() throws {
        let chunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.convId, senderAddress: Fixture.sender, message: rep("a", 484_928))
        #expect(chunks.count == 1000)
        #expect(chunks.allSatisfy { byteLen($0) <= ZMSGConstants.maxMemoSize })
        #expect(throws: ZMSGError.tooManyChunks(count: 1001)) {
            try ZMSGProtocol.createChunkedV4InitMessages(
                convId: Fixture.convId, senderAddress: Fixture.sender, message: rep("a", 484_929))
        }
    }
}

@Suite("ZMSG chunking keeps Unicode byte-exact")
struct ZMSGChunkUnicodeTests {
    // Android test ZMSGChunkingEmojiIntegrityTest.v4InitChunks_emojiHeavy_roundTripByteExact_noLoneSurrogates (:77-99).
    // Chunk count 7 is (simulated). Swift Strings cannot hold lone surrogates, so the Android "utf8Clean" check
    // becomes: every chunk is valid UTF-8 that round-trips through its scalars.
    @Test func initEmojiHeavyRoundTripsByteExact() throws {
        var cache = TestAddressCache()
        let chunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.convId, senderAddress: Fixture.sender, message: emojiHeavyMessage)
        #expect(chunks.count == 7)
        for memo in chunks { #expect(String(decoding: bytes(memo), as: UTF8.self).utf8.elementsEqual(memo.utf8)) }
        let parsed = try reassembled(chunks, &cache)
        #expect(bytes(parsed.message) == bytes(emojiHeavyMessage))
        #expect(parsed.senderAddress == Fixture.sender)
        #expect(parsed.conversationId == Fixture.convId)
    }

    // Android test ZMSGChunkingEmojiIntegrityTest.v4ReplyChunks_emojiHeavy_roundTripByteExact_noLoneSurrogates
    // (:101-115). Chunk count 6 is (simulated).
    @Test func replyEmojiHeavyRoundTripsByteExact() throws {
        let senderHash = ZMSGProtocol.generateAddressHash(Fixture.sender)
        var cache = TestAddressCache()
        cache.cacheAddress(hash: senderHash, address: Fixture.sender)
        let chunks = try ZMSGProtocol.createChunkedV4ReplyMessages(
            convId: Fixture.convId, senderAddress: Fixture.sender, message: emojiHeavyMessage)
        #expect(chunks.count == 6)
        let parsed = try reassembled(chunks, &cache)
        #expect(bytes(parsed.message) == bytes(emojiHeavyMessage))
        #expect(parsed.senderHash == senderHash)
        #expect(parsed.senderAddress == Fixture.sender)
    }

    // Android test ZMSGChunkingEmojiIntegrityTest.emojiStraddlingFirstChunkBoundary_isPushedWholeToNextChunk
    // (:131-152).
    @Test func emojiStraddlingTheFirstBoundaryMovesWhole() throws {
        var cache = TestAddressCache()
        let budget = ZMSGProtocol.v4InitFirstChunkBudget(senderAddress: Fixture.sender)
        let message = rep("a", budget - 1) + "\u{1F600}" + rep("b", 10)
        let chunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.convId, senderAddress: Fixture.sender, message: message)
        #expect(chunks.count == 2)
        #expect(bytes(chunks[0]) == bytes("ZMSG|v4c|1/2|TESTCONV|INIT|" + Fixture.sender + "|" + rep("a", budget - 1)))
        #expect(bytes(chunks[1]) == bytes("ZMSG|v4c|2/2|CONT|\u{1F600}" + rep("b", 10)))
        let parsed = try reassembled(chunks, &cache)
        #expect(bytes(parsed.message) == bytes(message))
        #expect(ZMSGProtocol.calculateV4ChunkCount(message: message, isInitMessage: true,
                                                   senderAddress: Fixture.sender) == chunks.count)
    }

    // Android test ZMSGChunkingEmojiIntegrityTest.v4Chunks_emojiHeavy_everyMemoStaysWithinMemoByteLimit (:154-171).
    @Test func fourByteEmojiChunksStayWithinTheMemoLimit() throws {
        var cache = TestAddressCache()
        let message = rep("\u{1F600}\u{1F389}\u{1F680}\u{1F49C}", 120)
        let chunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.convId, senderAddress: Fixture.sender, message: message)
        #expect(chunks.count > 1)
        for memo in chunks { #expect(byteLen(memo) <= ZMSGConstants.maxMemoSize) }
        let parsed = try reassembled(chunks, &cache)
        #expect(bytes(parsed.message) == bytes(message))
    }

    // Android test ZMSGChunkingEmojiIntegrityTest.v4ChunkCount_matchesBuilder_whereArithmeticCountUndercounts
    // (:177-206). The test's KDoc gives 58 chunks for the reply ("verified by simulating the code-point packer
    // offline"); our own simulation agrees, and also gives 58 for the INIT with the 68-byte sender.
    // A Character-based packer never splits inside the ZWJ family and gets a different count: this pins scalars.
    @Test func zwjFamilyPayloadSplitsByScalarLikeAndroid() throws {
        let senderHash = ZMSGProtocol.generateAddressHash(Fixture.sender)
        var seeded = TestAddressCache()
        seeded.cacheAddress(hash: senderHash, address: Fixture.sender)
        var empty = TestAddressCache()

        let initChunks = try ZMSGProtocol.createChunkedV4InitMessages(
            convId: Fixture.convId, senderAddress: Fixture.sender, message: desyncPayload)
        #expect(initChunks.count == ZMSGProtocol.calculateV4ChunkCount(
            message: desyncPayload, isInitMessage: true, senderAddress: Fixture.sender))
        #expect(initChunks.count == 58)   // (simulated)

        let replyChunks = try ZMSGProtocol.createChunkedV4ReplyMessages(
            convId: Fixture.convId, senderAddress: Fixture.sender, message: desyncPayload)
        #expect(replyChunks.count == ZMSGProtocol.calculateV4ChunkCount(message: desyncPayload, isInitMessage: false))
        #expect(replyChunks.count == 58)  // Android test KDoc :182-183

        // (simulated) Reply chunk 1 text = 25 families + U+1F468 ZWJ U+1F469 = 461 bytes; chunk 2 starts with the ZWJ.
        let replyHeader1 = "ZMSG|v4c|1/58|TESTCONV|" + senderHash + "|"
        #expect(byteLen(replyChunks[0]) == byteLen(replyHeader1) + 461)
        let cont2 = bytes(replyChunks[1])
        let header2 = bytes("ZMSG|v4c|2/58|CONT|")
        #expect(Array(cont2.prefix(header2.count + 3)) == header2 + [0xE2, 0x80, 0x8D])

        let initParsed = try reassembled(initChunks, &empty)
        #expect(bytes(initParsed.message) == bytes(desyncPayload))
        let replyParsed = try reassembled(replyChunks, &seeded)
        #expect(bytes(replyParsed.message) == bytes(desyncPayload))
    }

    // packChunks splits between code points, so "e" + U+0301 can straddle a boundary: chunk 2 then begins
    // "CONT|" + U+0301, which is ONE Swift Character "|\u{301}". The receiver must still see the "CONT|" marker
    // (Kotlin startsWith over UTF-16, ZMSGProtocol.kt:1465). 461 'a' + "e\u{301}" + 10 'b' (simulated).
    // provisional (typed from code)
    @Test func combiningMarkStraddlingABoundaryRoundTripsByteExact() throws {
        var cache = TestAddressCache()
        let message = rep("a", 461) + "e\u{301}" + rep("b", 10)
        let chunks = try ZMSGProtocol.createChunkedV4ReplyMessages(
            convId: "CONV0001", senderAddress: "abc", message: message)
        #expect(chunks.count == 2)
        #expect(bytes(chunks[0]) == bytes("ZMSG|v4c|1/2|CONV0001|ba7816bf8f01cfea|" + rep("a", 461) + "e"))
        #expect(bytes(chunks[1]) == bytes("ZMSG|v4c|2/2|CONT|") + [0xCC, 0x81] + bytes(rep("b", 10)))
        let parsed = try reassembled(Array(chunks.reversed()), &cache)
        #expect(bytes(parsed.message) == bytes(message))
    }

    // NFC and NFD forms are different bytes and must stay different (no normalisation anywhere): the builders
    // interpolate the message raw (ZMSGProtocol.kt:237, :251). provisional (typed from code)
    @Test func noUnicodeNormalisation() throws {
        let nfc = try ZMSGProtocol.createV4ReplyMessage(convId: "CONV0001", senderAddress: "abc", message: "\u{E9}")
        let nfd = try ZMSGProtocol.createV4ReplyMessage(convId: "CONV0001", senderAddress: "abc", message: "e\u{301}")
        #expect(bytes(nfc) != bytes(nfd))
        #expect(Array(bytes(nfd).suffix(3)) == [0x65, 0xCC, 0x81])
    }
}
