using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public static class PacketPayload
    {
        public static ReadOnlyMemory<byte> SlicePacketBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> afterPacketBytes)
        {
            var length = VariableLengthEncoding.Decode32(bytes.Span, out var decodedBytesLength);
            var afterLengthBytes = bytes.Slice(decodedBytesLength);

            if(afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            afterPacketBytes = afterLengthBytes.Slice(length);

            return afterLengthBytes.Slice(0, length);
        }

        public static WritingContext StartPacketWriting(Span<byte> bytes)
        {
            var context = new WritingContext(bytes);
            context.Cursor = context.Cursor.Move(4);

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

            public void Complete(out Span<byte> remainings)
            {
                if (Cursor.Offset < 4)
                {
                    throw new EncodingException();
                }

                var payloadLength = Cursor.Offset - 4;

                VariableLengthEncoding.Encode(start, (ulong)payloadLength, out var encodedLength);

                var afterLengthBytes = start.Slice(encodedLength);
                var payload = start.Slice(4, payloadLength);

                payload.CopyTo(afterLengthBytes);

                remainings = start.Slice(encodedLength + payloadLength);
            }
        }
    }
}
