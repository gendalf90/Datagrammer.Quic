using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class ExtensionLength
    {
        public static ReadOnlyMemory<byte> Slice(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> afterPayloadBytes)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var payloadLengthBytes = bytes.Slice(0, 2);
            var payloadLength = (int)NetworkBitConverter.ParseUnaligned(payloadLengthBytes.Span);

            if(bytes.Length < payloadLength + 2)
            {
                throw new EncodingException();
            }

            afterPayloadBytes = bytes.Slice(payloadLength + 2);

            return bytes.Slice(2, payloadLength);
        }

        public static MemoryBuffer Slice(MemoryCursor cursor)
        {
            var payloadLengthBytes = cursor.Move(2);
            var payloadLength = (int)NetworkBitConverter.ParseUnaligned(payloadLengthBytes.Span);
            var startOffsetOfBody = cursor.AsOffset();

            cursor.Move(payloadLength);

            return new MemoryBuffer(startOffsetOfBody, payloadLength);
        }

        public static WritingContext StartWriting(ref Span<byte> bytes)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var context = new WritingContext(bytes);

            bytes = bytes.Slice(2);

            return context;
        }

        public static CursorWritingContext StartWriting(MemoryCursor cursor)
        {
            var lengthBytes = cursor.Move(2);
            var startOffset = cursor.AsOffset();

            return new CursorWritingContext(cursor, startOffset, lengthBytes.Span);
        }

        public readonly ref struct WritingContext
        {
            private readonly Span<byte> start;

            public WritingContext(Span<byte> start)
            {
                this.start = start;
            }

            public void Complete(ref Span<byte> bytes)
            {
                var offset = start.Length - bytes.Length;

                if (offset < 2)
                {
                    throw new EncodingException();
                }

                var payloadLength = offset - 2;

                if (payloadLength > ushort.MaxValue)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(start, (ulong)payloadLength, 2);
            }
        }

        public readonly ref struct CursorWritingContext
        {
            private readonly MemoryCursor cursor;
            private readonly int startOffset;
            private readonly Span<byte> lengthBytes;

            public CursorWritingContext(
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

                if (payloadLength > ushort.MaxValue)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(lengthBytes, (ulong)payloadLength, 2);
            }
        }
    }
}
