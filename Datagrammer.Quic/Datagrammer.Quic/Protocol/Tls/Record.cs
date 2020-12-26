using Datagrammer.Quic.Protocol.Error;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct Record
    {
        public Record(RecordType type, ProtocolVersion protocolVersion, MemoryBuffer payload)
        {
            Type = type;
            ProtocolVersion = protocolVersion;
            Payload = payload;
        }

        public RecordType Type { get; }

        public ProtocolVersion ProtocolVersion { get; }

        public MemoryBuffer Payload { get; }

        public static bool TryParse(MemoryCursor cursor, RecordType type, out Record result)
        {
            result = new Record();

            if(!RecordType.TrySlice(cursor, type))
            {
                return false;
            }

            var protocolVersion = ProtocolVersion.Parse(cursor);
            var body = RecordLength.SliceBytes(cursor);

            result = new Record(type, protocolVersion, body);

            return true;
        }

        public static bool TryParseEncrypted(MemoryCursor cursor, IAead aead, int sequenceNumber, out Record result)
        {
            var startOffsetOfMessage = cursor.AsOffset();

            result = new Record();

            if (!RecordType.TrySlice(cursor, RecordType.ApplicationData))
            {
                return false;
            }

            var legacyVersion = ProtocolVersion.Parse(cursor);

            if (legacyVersion != ProtocolVersion.Tls12)
            {
                throw new EncodingException();
            }

            var body = RecordLength.DecryptBytes(cursor, startOffsetOfMessage, aead, sequenceNumber);

            using var bodyContext = body.SetCursor(cursor);

            var startOffsetOfBody = cursor.AsOffset();

            cursor.Reverse();

            var actualType = RecordType.ParseReverse(cursor);

            result = new Record(actualType, legacyVersion, new MemoryBuffer(startOffsetOfBody, cursor - startOffsetOfBody));

            return true;
        }

        public static RecordLength.WritingContext StartWriting(MemoryCursor cursor, RecordType type, ProtocolVersion protocolVersion)
        {
            type.WriteBytes(cursor);
            protocolVersion.WriteBytes(cursor);

            return RecordLength.StartWriting(cursor);
        }

        public static RecordLength.EncryptedWritingContext StartEncryptedWriting(MemoryCursor cursor, RecordType type, IAead aead, int sequenceNumber)
        {
            var startLengthOfMessage = cursor.AsOffset();

            RecordType.ApplicationData.WriteBytes(cursor);
            ProtocolVersion.Tls12.WriteBytes(cursor);

            return RecordLength.StartEncryptedWriting(cursor, startLengthOfMessage, type, aead, sequenceNumber);
        }

        public static void SliceUnknown(MemoryCursor cursor)
        {
            RecordType.Parse(cursor);
            ProtocolVersion.Parse(cursor);
            RecordLength.SliceBytes(cursor);
        }
    }
}
