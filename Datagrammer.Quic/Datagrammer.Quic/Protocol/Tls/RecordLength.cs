using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class RecordLength
    {
        private const int MaxLength = 0x4000;

        public static MemoryBuffer SliceBytes(MemoryCursor cursor)
        {
            var lengthBytes = cursor.Move(2);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);

            if(length > MaxLength)
            {
                throw new EncodingException();
            }

            var startOffsetOfBody = cursor.AsOffset();

            cursor.Move(length);

            return new MemoryBuffer(startOffsetOfBody, length);
        }

        public static MemoryBuffer DecryptBytes(MemoryCursor cursor, int startOffsetOfMessage, IAead aead, ulong sequenceNumber)
        {
            var headerLength = cursor - startOffsetOfMessage + 2;
            var lengthBytes = cursor.Move(2);
            var headerBytes = cursor.Peek(-headerLength);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);

            if (length > MaxLength)
            {
                throw new EncodingException();
            }

            if (length < aead.TagLength)
            {
                throw new EncodingException();
            }

            var startOffsetOfBody = cursor.AsOffset();
            var encryptedLength = length - aead.TagLength;
            var encryptedBytes = cursor.Move(encryptedLength);
            var tag = cursor.Move(aead.TagLength);

            aead.Decrypt(encryptedBytes.Span, tag.Span, sequenceNumber, headerBytes.Span);

            return new MemoryBuffer(startOffsetOfBody, encryptedLength);
        }

        public static WritingContext StartWriting(MemoryCursor cursor)
        {
            var lengthBytes = cursor.Move(2);
            var startOffset = cursor.AsOffset();

            return new WritingContext(cursor, startOffset, lengthBytes.Span);
        }

        public static EncryptedWritingContext StartEncryptedWriting(
            MemoryCursor cursor,
            int startLengthOfMessage, 
            RecordType type,
            IAead aead, 
            ulong sequenceNumber)
        {
            var lengthBytes = cursor.Move(2);
            var startLengthOfBody = cursor.AsOffset();

            return new EncryptedWritingContext(cursor, lengthBytes.Span, startLengthOfBody, startLengthOfMessage, type, aead, sequenceNumber);
        }

        public readonly ref struct WritingContext
        {
            private readonly MemoryCursor cursor;
            private readonly int startOffset;
            private readonly Span<byte> lengthBytes;

            public WritingContext(
                MemoryCursor cursor,
                int startOffset,
                Span<byte> lengthBytes)
            {
                this.cursor = cursor;
                this.startOffset = startOffset;
                this.lengthBytes = lengthBytes;
            }

            public void Dispose()
            {
                var payloadLength = cursor - startOffset;

                if (payloadLength > MaxLength)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(lengthBytes, (ulong)payloadLength, 2);
            }
        }

        public readonly ref struct EncryptedWritingContext
        {
            private readonly MemoryCursor cursor;
            private readonly int startLengthOfBody;
            private readonly int startLengthOfMessage;
            private readonly Span<byte> lengthBytes;
            private readonly RecordType type;
            private readonly IAead aead;
            private readonly ulong sequenceNumber;

            public EncryptedWritingContext(
                MemoryCursor cursor,
                Span<byte> lengthBytes,
                int startLengthOfBody,
                int startLengthOfMessage,
                RecordType type,
                IAead aead,
                ulong sequenceNumber)
            {
                this.cursor = cursor;
                this.lengthBytes = lengthBytes;
                this.startLengthOfBody = startLengthOfBody;
                this.startLengthOfMessage = startLengthOfMessage;
                this.type = type;
                this.aead = aead;
                this.sequenceNumber = sequenceNumber;
            }

            public void Dispose()
            {
                type.WriteBytes(cursor);

                var payloadLength = cursor - startLengthOfBody;

                if (payloadLength > MaxLength)
                {
                    throw new EncodingException();
                }

                var payloadData = cursor.Move(-payloadLength);
                var headerLength = cursor - startLengthOfMessage;
                var headerData = cursor.Peek(-headerLength);
                var encryptedPayloadLength = payloadLength + aead.TagLength;

                if (encryptedPayloadLength > MaxLength)
                {
                    throw new EncodingException();
                }

                cursor.Move(encryptedPayloadLength);

                var tag = cursor.Peek(-aead.TagLength);

                NetworkBitConverter.WriteUnaligned(lengthBytes, (ulong)encryptedPayloadLength, 2);

                aead.Encrypt(payloadData.Span, tag.Span, sequenceNumber, headerData.Span);
            }
        }
    }
}
