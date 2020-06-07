using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class ExtensionPayload
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

        public static WritingContext StartWriting(Span<byte> destination)
        {
            var context = new WritingContext(destination);

            context.Cursor = context.Cursor.Move(2);

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
                if (Cursor.Offset < 2)
                {
                    throw new EncodingException();
                }

                var payloadLength = Cursor.Offset - 2;

                if (payloadLength > ushort.MaxValue)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(start, (ulong)payloadLength, 2);

                return Cursor.Offset;
            }
        }
    }
}
