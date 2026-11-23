// PAR-0002: single-memo v4 envelopes (INIT, reply, KEX, KEXACK, ADDR) as Android 2.13.0 builds and parses them.
// Census CENSUS1_WIRE_v2.13.0.md §1.3. Android lines: UI/screen/chat/model/ZMSGProtocol.kt at 479a084d3.
// Contract: see ZMSGContractTests.swift.

import Testing
@testable import ZChatProtocol

@Suite("ZMSG v4 single-memo builders")
struct ZMSGV4BuilderTests {
    let conv = "CONV0001"
    let sender = Fixture.sender

    // ZMSGProtocol.kt:235-238. provisional (typed from code)
    @Test func initLayoutIsByteExact() throws {
        let memo = try ZMSGProtocol.createV4InitMessage(convId: conv, senderAddress: sender, message: "hi")
        #expect(bytes(memo) == bytes("ZMSG|v4|CONV0001|INIT|" + sender + "|hi"))
    }

    // ZMSGProtocol.kt:248-252. The hash function itself is pinned in ZMSGHashTests. provisional (typed from code)
    @Test func replyLayoutIsByteExact() throws {
        let memo = try ZMSGProtocol.createV4ReplyMessage(convId: conv, senderAddress: "abc", message: "hi")
        #expect(bytes(memo) == bytes("ZMSG|v4|CONV0001|ba7816bf8f01cfea|hi"))
    }

    // ZMSGProtocol.kt:306-310 and :319-323. provisional (typed from code)
    @Test func kexAndKexAckLayoutsAreByteExact() throws {
        let kex = try ZMSGProtocol.createV4KEXMessage(convId: conv, senderAddress: "abc", kexPayload: "KEX:pub:sig")
        #expect(bytes(kex) == bytes("ZMSG|v4|CONV0001|KEX|ba7816bf8f01cfea|KEX:pub:sig"))
        let ack = try ZMSGProtocol.createV4KEXAckMessage(convId: conv, senderAddress: "abc", kexAckPayload: "KEXACK:p:s")
        #expect(bytes(ack) == bytes("ZMSG|v4|CONV0001|KEXACK|ba7816bf8f01cfea|KEXACK:p:s"))
    }

    // Android test ZMSGProtocolAddrTest.addr_exactWireShape (T/screen/chat/model/ZMSGProtocolAddrTest.kt:37-40)
    // (inputs changed: old sender "abc" so the hash is the FIPS literal).
    @Test func addrLayoutIsByteExact() throws {
        let memo = try ZMSGProtocol.createV4ADDRMessage(
            convId: "ABC12345", oldSenderAddress: "abc", newAddress: "u1newaddr", signature: "c2lnbmF0dXJlYmFzZTY0")
        #expect(bytes(memo) == bytes("ZMSG|v4|ABC12345|ADDR|ba7816bf8f01cfea|u1newaddr|c2lnbmF0dXJlYmFzZTY0"))
    }

    // Message text is carried raw: pipes, empty fields, non-ASCII, combining marks. ZMSGProtocol.kt:237, :251.
    // provisional (typed from code)
    @Test func messageTextIsCarriedRawAndByteExact() throws {
        let text = "a||b|\u{301}\u{E9}\u{1F600}"
        let memo = try ZMSGProtocol.createV4InitMessage(convId: conv, senderAddress: sender, message: text)
        #expect(bytes(memo) == bytes("ZMSG|v4|CONV0001|INIT|" + sender + "|") + bytes(text))
        let empty = try ZMSGProtocol.createV4ReplyMessage(convId: conv, senderAddress: "abc", message: "")
        #expect(bytes(empty) == bytes("ZMSG|v4|CONV0001|ba7816bf8f01cfea|"))
    }

    // validateConvId (ZMSGProtocol.kt:130-137) guards every v4 builder: exactly 8 chars of A-Z0-9.
    // provisional (typed from code)
    @Test(arguments: ["CONV001", "CONV00011", "conv0001", "CONV-001", "CONV 001", "CONV\u{C9}001", ""])
    func everyV4BuilderRejectsABadConversationId(bad: String) {
        #expect(throws: ZMSGError.invalidConversationId) {
            try ZMSGProtocol.createV4InitMessage(convId: bad, senderAddress: sender, message: "m")
        }
        #expect(throws: ZMSGError.invalidConversationId) {
            try ZMSGProtocol.createV4ReplyMessage(convId: bad, senderAddress: sender, message: "m")
        }
        #expect(throws: ZMSGError.invalidConversationId) {
            try ZMSGProtocol.createV4KEXMessage(convId: bad, senderAddress: sender, kexPayload: "p")
        }
        #expect(throws: ZMSGError.invalidConversationId) {
            try ZMSGProtocol.createV4KEXAckMessage(convId: bad, senderAddress: sender, kexAckPayload: "p")
        }
        #expect(throws: ZMSGError.invalidConversationId) {
            try ZMSGProtocol.createV4ADDRMessage(convId: bad, oldSenderAddress: sender, newAddress: "n", signature: "s")
        }
        #expect(throws: ZMSGError.invalidConversationId) {
            try ZMSGProtocol.createChunkedV4InitMessages(convId: bad, senderAddress: sender, message: "m")
        }
        #expect(throws: ZMSGError.invalidConversationId) {
            try ZMSGProtocol.createChunkedV4ReplyMessages(convId: bad, senderAddress: sender, message: "m")
        }
    }
}

@Suite("ZMSG v4 KEX / KEXACK / ADDR recognisers and parsers")
struct ZMSGV4ControlParseTests {
    let hash = "ba7816bf8f01cfea"

    // ZMSGProtocol.kt:383-403: split("|", limit = 4) -> the payload keeps its own pipes. provisional (typed from code)
    @Test func kexParseKeepsPipesInsideThePayload() throws {
        let memo = "ZMSG|v4|CONV0001|KEX|\(hash)|KEX:a|b:c"
        #expect(ZMSGProtocol.isKEXMessage(memo))
        let env = try #require(ZMSGProtocol.parseKEXMessage(memo))
        #expect(bytes(env.conversationId) == bytes("CONV0001"))
        #expect(bytes(env.payload) == bytes("KEX:a|b:c"))
    }

    // Kotlin split keeps empty fields: an empty payload is 4 parts (accepted, payload ""); "...|KEX|" is 3 parts (null).
    // ZMSGProtocol.kt:390-391. provisional (typed from code)
    @Test func kexParseKeepsEmptyFieldsLikeKotlinSplit() throws {
        let emptyPayload = try #require(ZMSGProtocol.parseKEXMessage("ZMSG|v4|CONV0001|KEX|\(hash)|"))
        #expect(bytes(emptyPayload.payload) == [])
        let emptyHash = try #require(ZMSGProtocol.parseKEXMessage("ZMSG|v4|CONV0001|KEX||payload"))
        #expect(bytes(emptyHash.payload) == bytes("payload"))
        #expect(ZMSGProtocol.isKEXMessage("ZMSG|v4|CONV0001|KEX|"))
        #expect(ZMSGProtocol.parseKEXMessage("ZMSG|v4|CONV0001|KEX|") == nil)
    }

    // ZMSGProtocol.kt:328-347: KEX| and KEXACK| are told apart by the marker; neither parser takes the other's memo.
    // provisional (typed from code)
    @Test func kexAndKexAckAreDistinct() throws {
        let kex = "ZMSG|v4|CONV0001|KEX|\(hash)|K"
        let ack = "ZMSG|v4|CONV0001|KEXACK|\(hash)|A"
        #expect(ZMSGProtocol.isKEXMessage(kex) && !ZMSGProtocol.isKEXAckMessage(kex))
        #expect(ZMSGProtocol.isKEXAckMessage(ack) && !ZMSGProtocol.isKEXMessage(ack))
        #expect(ZMSGProtocol.parseKEXMessage(ack) == nil)
        #expect(ZMSGProtocol.parseKEXAckMessage(kex) == nil)
        let parsed = try #require(ZMSGProtocol.parseKEXAckMessage(ack))
        #expect(parsed == KexEnvelope(conversationId: "CONV0001", payload: "A"))
    }

    // ZMSGProtocol.kt:328-335 checks only the prefix, a '|' at offset 8 and the marker: the conv id charset is NOT
    // checked on this path (validateConvId is builder-only). provisional (typed from code)
    @Test func kexRecogniserDoesNotValidateConvIdCharset() throws {
        let memo = "ZMSG|v4|abcdefgh|KEX|\(hash)|P"
        #expect(ZMSGProtocol.isKEXMessage(memo))
        let env = try #require(ZMSGProtocol.parseKEXMessage(memo))
        #expect(env.conversationId == "abcdefgh")
        // A '|' not at offset 8 is not a KEX memo.
        #expect(!ZMSGProtocol.isKEXMessage("ZMSG|v4|CONV001|KEX|\(hash)|P"))
        #expect(!ZMSGProtocol.isKEXMessage("ZMSG|v3|CONV0001|KEX|\(hash)|P"))
    }

    // Android test ZMSGProtocolAddrTest.addr_roundTrip_recoversConvIdOldHashNewAddressSignature (:26-34).
    @Test func addrRoundTrip() throws {
        let oldSender = "u1oldaddressforaddrchange000000000000000000000000000000000000000000"
        let newAddress = "u1newaddressforaddrchange000000000000000000000000000000000000000000"
        let wire = try ZMSGProtocol.createV4ADDRMessage(
            convId: "ABC12345", oldSenderAddress: oldSender, newAddress: newAddress, signature: "c2lnbmF0dXJlYmFzZTY0")
        #expect(ZMSGProtocol.isADDRMessage(wire))
        let parsed = try #require(ZMSGProtocol.parseADDRMessage(wire))
        #expect(parsed == ParsedADDRMessage(
            conversationId: "ABC12345",
            oldSenderHash: ZMSGProtocol.generateAddressHash(oldSender),
            newAddress: newAddress,
            signature: "c2lnbmF0dXJlYmFzZTY0"))
    }

    // Android test ZMSGProtocolAddrTest.addr_signatureContainingPipes_survivesBecauseSplitLimitIsFive (:43-50)
    // (inputs changed: shorter synthetic addresses).
    @Test func addrSignatureKeepsItsPipes() throws {
        let wire = try ZMSGProtocol.createV4ADDRMessage(
            convId: "ABC12345", oldSenderAddress: "abc", newAddress: "u1new", signature: "sig|with|pipes")
        let parsed = try #require(ZMSGProtocol.parseADDRMessage(wire))
        #expect(bytes(parsed.signature) == bytes("sig|with|pipes"))
        #expect(bytes(parsed.newAddress) == bytes("u1new"))
    }

    // Android test ZMSGProtocolAddrTest.addr_fewerThanFiveParts_returnsNull (:53-58) (inputs changed).
    @Test func addrWithoutSignatureIsDetectedButRejected() {
        let wire = "ZMSG|v4|ABC12345|ADDR|\(hash)|u1new"
        #expect(ZMSGProtocol.isADDRMessage(wire))
        #expect(ZMSGProtocol.parseADDRMessage(wire) == nil)
    }

    // Android tests ZMSGProtocolAddrTest.addr_nonAddrMessage_returnsNull (:61-64) and
    // isADDRMessage_onlyForAddrMarker (:67-72) (inputs changed).
    @Test func addrRecogniserOnlyForAddrMarker() {
        #expect(ZMSGProtocol.parseADDRMessage("ZMSG|v4|ABC12345|INIT|u1new|hello") == nil)
        #expect(ZMSGProtocol.parseADDRMessage("plain text") == nil)
        #expect(!ZMSGProtocol.isADDRMessage("ZMSG|v4|ABC12345|KEX|\(hash)|payload"))
        #expect(!ZMSGProtocol.isADDRMessage("ZMSG|v3|INIT|u1new|hi"))
    }
}

@Suite("ZMSG v4 INIT lightweight parse (relay path)")
struct ZMSGV4InitLightParseTests {
    // ZMSGProtocol.kt:261-277: (address, message) of a single v4 INIT; message keeps later pipes.
    // provisional (typed from code)
    @Test func parsesAddressAndMessage() throws {
        let memo = "ZMSG|v4|CONV0001|INIT|u1addr|hello|world"
        let r = try #require(ZMSGProtocol.parseV4Init(memo))
        #expect(bytes(r.address) == bytes("u1addr"))
        #expect(bytes(r.message) == bytes("hello|world"))
        #expect(ZMSGProtocol.parseV4InitConvId(memo) == "CONV0001")
    }

    // ZMSGProtocol.kt:264-275: conv id must be 8 CONV_ID_CHARS ending at the first '|'; INIT marker required; a
    // separator after the address required; a blank address refused. provisional (typed from code)
    @Test(arguments: [
        "ZMSG|v4|CONV001|INIT|u1addr|m",       // conv id 7
        "ZMSG|v4|conv0001|INIT|u1addr|m",      // lowercase conv id
        "ZMSG|v4|CONV0001|ba7816bf8f01cfea|m", // reply, not INIT
        "ZMSG|v4|CONV0001|INIT|u1addr",        // no separator after the address
        "ZMSG|v4|CONV0001|INIT||m",            // empty address
        "ZMSG|v4|CONV0001|INIT| \t|m",         // blank address
        "ZMSG|v4c|1/2|CONV0001|INIT|u1addr|m", // chunked
        " ZMSG|v4|CONV0001|INIT|u1addr|m",     // leading space: no trim
    ])
    func rejectsWhatAndroidRejects(memo: String) {
        #expect(ZMSGProtocol.parseV4Init(memo) == nil)
        #expect(ZMSGProtocol.parseV4InitConvId(memo) == nil)
    }

    // The separator search is over code points: a combining mark after '|' does not hide the '|'.
    // ZMSGProtocol.kt:271 (Kotlin indexOf over UTF-16). provisional (typed from code)
    @Test func combiningMarkAfterSeparatorStaysInTheMessage() throws {
        let r = try #require(ZMSGProtocol.parseV4Init("ZMSG|v4|CONV0001|INIT|u1addr|\u{301}x"))
        #expect(bytes(r.address) == bytes("u1addr"))
        #expect(bytes(r.message) == [0xCC, 0x81, 0x78])
    }
}
