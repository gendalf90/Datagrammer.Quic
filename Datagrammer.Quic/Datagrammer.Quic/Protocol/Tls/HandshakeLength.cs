using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class HandshakeLength
    {
        private const int MaxLength = 0xFFFFFF;

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

        public static WritingContext StartWriting(Span<byte> destination)
        {
            var context = new WritingContext(destination);

            context.Cursor = context.Cursor.Move(3);

            return context;
        }

        public ref struct WritingContext
        {
            private Span<byte> start;

            public WritingContext(Span<byte> start)
            {
                this.start = start;

                Cursor = new WritingCursor(start, 0);
            }

            public WritingCursor Cursor { get; set; }

            public int Complete()
            {
                if (Cursor.Offset < 3)
                {
                    throw new EncodingException();
                }

                var payloadLength = Cursor.Offset - 3;

                if (payloadLength > MaxLength)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(start, (ulong)payloadLength, 3);

                return Cursor.Offset;
            }
        }
    }
}
