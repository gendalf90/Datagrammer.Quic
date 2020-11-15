using Datagrammer.Quic.Protocol.Error;
using System;
using System.Threading;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class RecordLength
    {
        private const int MaxLength = 0x4000;

        public static ReadOnlyMemory<byte> SliceBytes(ref ReadOnlyMemory<byte> bytes)
        {
            return SliceBytes(bytes, out bytes);
        }

        public static ReadOnlyMemory<byte> SliceBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> afterApplicationBytes)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var lengthBytes = bytes.Slice(0, 2);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);
            var afterLengthBytes = bytes.Slice(2);

            if (afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            afterApplicationBytes = afterLengthBytes.Slice(length);

            return afterLengthBytes.Slice(0, length);
        }

        public static WritingContext StartWriting(MemoryCursor cursor, RecordType type)
        {
            var lengthBytes = cursor.Move(2);
            var startLength = cursor.AsOffset();

            return new WritingContext(cursor, startLength, lengthBytes, type);
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

            return new EncryptedWritingContext(cursor, lengthBytes, startLengthOfBody, startLengthOfMessage, type, aead, sequenceNumber);
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

                payloadData.CopyTo(payloadBuffer);

                var headerLength = cursor - startLengthOfMessage;
                var headerData = cursor.Peek(-headerLength);
                var encryptingContext = aead.StartEncrypting(payloadBuffer, cursor);
                var encryptedPayloadLength = encryptingContext.ResultBuffer.Length;

                if (encryptedPayloadLength > MaxLength)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(lengthBytes, (ulong)encryptedPayloadLength, 2);

                encryptingContext.Complete(headerData, sequenceNumber);
            }
        }
    }
}
