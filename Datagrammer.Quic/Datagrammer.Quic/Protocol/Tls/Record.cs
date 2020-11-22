using Datagrammer.Quic.Protocol.Error;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct Record
    {
        public Record(RecordType type, MemoryBuffer payload)
        {
            Type = type;
            Payload = payload;
        }

        public RecordType Type { get; }

        public MemoryBuffer Payload { get; }

        public static bool TryParse(MemoryCursor cursor, out Record result)
        {
            result = new Record();

            if(!RecordType.TrySlice(cursor, RecordType.ApplicationData))
            {
                return false;
            }

            var legacyVersion = ProtocolVersion.Parse(cursor);

            if (legacyVersion != ProtocolVersion.Tls12)
            {
                throw new EncodingException();
            }

            var body = RecordLength.SliceBytes(cursor);

            using var bodyContext = body.SetCursor(cursor);

            var startOffsetOfBody = cursor.AsOffset();

            cursor.Reverse();

            var actualType = RecordType.ParseReverse(cursor);

            result = new Record(actualType, new MemoryBuffer(startOffsetOfBody, cursor - startOffsetOfBody));

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

            result = new Record(actualType, new MemoryBuffer(startOffsetOfBody, cursor - startOffsetOfBody));

            return true;
        }

        public static RecordLength.WritingContext StartWriting(MemoryCursor cursor, RecordType type)
        {
            RecordType.ApplicationData.WriteBytes(cursor);
            ProtocolVersion.Tls12.WriteBytes(cursor);

            return RecordLength.StartWriting(cursor, type);
        }

        public static RecordLength.EncryptedWritingContext StartEncryptedWriting(MemoryCursor cursor, RecordType type, IAead aead, int sequenceNumber)
        {
            var startLengthOfMessage = cursor.AsOffset();

            RecordType.ApplicationData.WriteBytes(cursor);
            ProtocolVersion.Tls12.WriteBytes(cursor);

            return RecordLength.StartEncryptedWriting(cursor, startLengthOfMessage, type, aead, sequenceNumber);
        }
    }
}
