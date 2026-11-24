// PAR-0002: ZMSG constants as Android 2.13.0 (UI/screen/chat/model/ZMSGConstants.kt at 479a084d3).

public enum ZMSGConstants {
    public static let maxMemoSize = 512                                       // :19
    public static let convIdLength = 8                                        // :26
    public static let convIdChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"    // :29
    public static let hashLength = 12                                         // :34 (legacy, parse only)
    public static let hashLengthNew = 16                                      // :39
    public static let maxChunks = 1000                                        // ZMSGProtocol.kt:67

    public enum Prefixes {                                                    // :47-66
        public static let v4 = "ZMSG|v4|"
        public static let v4c = "ZMSG|v4c|"
        public static let v3 = "ZMSG|v3|"
        public static let v3c = "ZMSG|v3c|"
        public static let v2 = "ZMSG|v2|"
        public static let group = "ZMSG:3.0:GROUP:"
        public static let reaction = "ZREACT|"
        public static let receipt = "ZRCPT|"
        public static let status = "ZSTAT|"
        public static let timelock = "ZTL|"
        public static let unlock = "ZUNLOCK|"
        public static let request = "ZREQ|"
        public static let file = "ZFILE|"
        public static let disappear = "ZEXP|"
        public static let modeChange = "ZMODE|"
        public static let profile = "ZPROF|"
    }

    public enum Markers {                                                     // :74-80
        public static let initial = "INIT|"
        public static let cont = "CONT|"
        public static let ref = "REF|"
        public static let reply = "RPL|"
        public static let kex = "KEX|"
        public static let kexAck = "KEXACK|"
        public static let addr = "ADDR|"
    }

    public enum ChunkSizes {                                                  // :105-124 (bytes of text)
        public static let v3Init = 340
        public static let v3ReplyFirst = 470
        public static let continuation = 485
        public static let v4Init = 330          // fallback only; the real INIT budget is v4InitFirstChunkBudget
        public static let v4ReplyFirst = 462
    }
}

/// The wire prefixes and markers as UTF-16 units, for Kotlin-exact matching.
enum Wire {
    static let v4 = KS.units(ZMSGConstants.Prefixes.v4)
    static let v4c = KS.units(ZMSGConstants.Prefixes.v4c)
    static let v3 = KS.units(ZMSGConstants.Prefixes.v3)
    static let v3c = KS.units(ZMSGConstants.Prefixes.v3c)
    static let v2 = KS.units(ZMSGConstants.Prefixes.v2)
    static let group = KS.units(ZMSGConstants.Prefixes.group)
    static let v3Init = KS.units(ZMSGConstants.Prefixes.v3 + ZMSGConstants.Markers.initial)
    static let v3Ref = KS.units(ZMSGConstants.Prefixes.v3 + ZMSGConstants.Markers.ref)
    static let v3Rpl = KS.units(ZMSGConstants.Prefixes.v3 + ZMSGConstants.Markers.reply)

    static let initial = KS.units(ZMSGConstants.Markers.initial)
    static let cont = KS.units(ZMSGConstants.Markers.cont)
    static let ref = KS.units(ZMSGConstants.Markers.ref)
    static let kex = KS.units(ZMSGConstants.Markers.kex)
    static let kexAck = KS.units(ZMSGConstants.Markers.kexAck)
    static let addr = KS.units(ZMSGConstants.Markers.addr)

    /// isRecognizedZmsgEnvelope, ZMSGProtocol.kt:778-788.
    static let recognised: [UTF16Units] = [
        KS.units("ZMSG|"), KS.units("ZMSG:"),
        KS.units(ZMSGConstants.Prefixes.reaction), KS.units(ZMSGConstants.Prefixes.receipt),
        KS.units(ZMSGConstants.Prefixes.status), KS.units(ZMSGConstants.Prefixes.timelock),
        KS.units(ZMSGConstants.Prefixes.unlock), KS.units(ZMSGConstants.Prefixes.request),
        KS.units(ZMSGConstants.Prefixes.file),
    ]

    /// ZBootMessage.kt:53-56.
    static let zbootAny = KS.units("ZBOOT|")
    static let zbootV4 = KS.units("ZBOOT|v4|")
    static let zbootV3 = KS.units("ZBOOT|v3|")
    static let zbootV2 = KS.units("ZBOOT|v2|")
    static let wss = KS.units("wss://")
}
