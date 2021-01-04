using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class HandshakeLength
    {
        private const int MaxLength = 0xFFFFFF;

        public static MemoryBuffer SliceBytes(MemoryCursor cursor)
        {
            var lengthBytes = cursor.Move(3);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);
            var startOffsetOfBody = cursor.AsOffset();

            cursor.Move(length);

            return new MemoryBuffer(startOffsetOfBody, length);
        }

        public static ReadOnlyMemory<byte> SliceHandshakeBytes(ref ReadOnlyMemory<byte> bytes)
        {
            return SliceHandshakeBytes(bytes, out bytes);
        }

        public static ReadOnlyMemory<byte> SliceHandshakeBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> afterHandshakeBytes)
        {
            if(bytes.Length < 3)
            {
                throw new EncodingException();
            }

            var lengthBytes = bytes.Slice(0, 3);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);
            var afterLengthBytes = bytes.Slice(3);

            if (afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            afterHandshakeBytes = afterLengthBytes.Slice(length);

            return afterLengthBytes.Slice(0, length);
        }

        public static WritingContext StartWriting(ref Span<byte> destination)
        {
            if(destination.Length < 3)
            {
                throw new EncodingException();
            }

            var context = new WritingContext(destination);

            destination = destination.Slice(3);

            return context;
        }

        public static CursorWritingContext StartWriting(MemoryCursor cursor)
        {
            var lengthBytes = cursor.Move(3).Span;
            var startOffset = cursor.AsOffset();

            return new CursorWritingContext(cursor, startOffset, lengthBytes);
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

                if (offset < 3)
                {
                    throw new EncodingException();
                }

                var payloadLength = offset - 3;

                if (payloadLength > MaxLength)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(start, (ulong)payloadLength, 3);
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

                if (payloadLength > MaxLength)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(lengthBytes, (ulong)payloadLength, 3);
            }
        }
    }
}
