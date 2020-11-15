using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct Record
    {
        public Record(RecordType type, ReadOnlyMemory<byte> payload)
        {
            Type = type;
            Payload = payload;
        }

        public RecordType Type { get; }

        public ReadOnlyMemory<byte> Payload { get; }

        public static bool TryParse(ref ReadOnlyMemory<byte> bytes, out Record result)
        {
            result = new Record();

            if(!RecordType.TrySlice(ref bytes, RecordType.ApplicationData))
            {
                return false;
            }

            var legacyVersion = ProtocolVersion.Parse(ref bytes);

            if (legacyVersion != ProtocolVersion.Tls12)
            {
                throw new EncodingException();
            }

            var body = RecordLength.SliceBytes(ref bytes);
            var actualType = RecordType.ParseFinalBytes(ref body);

            result = new Record(actualType, body);

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
