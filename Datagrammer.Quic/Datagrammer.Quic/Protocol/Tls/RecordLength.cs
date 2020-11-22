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

        public static MemoryBuffer DecryptBytes(MemoryCursor cursor, int startOffsetOfMessage, IAead aead, int sequenceNumber)
        {
            var headerLength = cursor - startOffsetOfMessage + 2;
            var lengthBytes = cursor.Move(2);
            var headerBytes = cursor.Peek(-headerLength);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);

            if (length > MaxLength)
            {
                throw new EncodingException();
            }

            using var cursorLimitContext = cursor.WithLimit(length);

            var encryptedBytes = cursor.Peek(length);
            var startOffsetOfBody = cursor.AsOffset();

            Span<byte> encryptedBuffer = stackalloc byte[length];

            encryptedBytes.Span.CopyTo(encryptedBuffer);

            var decryptionContext = aead.StartDecrypting(encryptedBuffer, cursor);

            decryptionContext.Complete(headerBytes.Span, sequenceNumber);
            cursor.Set(startOffsetOfBody);
            cursor.Move(length);

            return new MemoryBuffer(startOffsetOfBody, decryptionContext.ResultBuffer.Length);
        }

        public static WritingContext StartWriting(MemoryCursor cursor, RecordType type)
        {
            var lengthBytes = cursor.Move(2);
            var startLength = cursor.AsOffset();

            return new WritingContext(cursor, startLength, lengthBytes.Span, type);
        }

        public static EncryptedWritingContext StartEncryptedWriting(
            MemoryCursor cursor,
            int startLengthOfMessage, 
            RecordType type,
            IAead aead, 
            int sequenceNumber)
        {
            var lengthBytes = cursor.Move(2);
            var startLengthOfBody = cursor.AsOffset();

            return new EncryptedWritingContext(cursor, lengthBytes.Span, startLengthOfBody, startLengthOfMessage, type, aead, sequenceNumber);
        }

        public readonly ref struct WritingContext
        {
            private readonly MemoryCursor cursor;
            private readonly int startLength;
            private readonly Span<byte> lengthBytes;
            private readonly RecordType type;

            public WritingContext(
                MemoryCursor cursor,
                int startLength,
                Span<byte> lengthBytes,
                RecordType type)
            {
                this.cursor = cursor;
                this.startLength = startLength;
                this.lengthBytes = lengthBytes;
                this.type = type;
            }

            public void Dispose()
            {
                type.WriteBytes(cursor);

                var payloadLength = cursor - startLength;

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
            private readonly int sequenceNumber;

            public EncryptedWritingContext(
                MemoryCursor cursor,
                Span<byte> lengthBytes,
                int startLengthOfBody,
                int startLengthOfMessage,
                RecordType type,
                IAead aead,
                int sequenceNumber)
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

                Span<byte> payloadBuffer = stackalloc byte[payloadLength];

                var payloadData = cursor.Move(-payloadLength);

                payloadData.Span.CopyTo(payloadBuffer);

                var headerLength = cursor - startLengthOfMessage;
                var headerData = cursor.Peek(-headerLength);
                var encryptingContext = aead.StartEncrypting(payloadBuffer, cursor);
                var encryptedPayloadLength = encryptingContext.ResultBuffer.Length;

                if (encryptedPayloadLength > MaxLength)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(lengthBytes, (ulong)encryptedPayloadLength, 2);

                encryptingContext.Complete(headerData.Span, sequenceNumber);
            }
        }
    }
}
