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

        public static MemoryBuffer SlicePacketBytes(MemoryCursor cursor, int startPacketOffset)
        {
            var readLength = cursor - startPacketOffset;
            var packetLength = cursor.DecodeVariable32();
            var payloadLength = packetLength - readLength;

            return cursor.Slice(payloadLength);
        }

        public static WritingContext StartPacketWriting(ref Span<byte> bytes)
        {
            if(bytes.Length < 4)
            {
                throw new EncodingException();
            }

            var context = new WritingContext(bytes);

            bytes = bytes.Slice(4);

            return context;
        }

        public static CursorWritingContext StartPacketWriting(MemoryCursor cursor, int startPacketOffset)
        {
            return new CursorWritingContext(cursor, startPacketOffset, cursor.AsOffset());
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

                if (offset < 4)
                {
                    throw new EncodingException();
                }

                var payloadLength = offset - 4;

                VariableLengthEncoding.Encode(start, (ulong)payloadLength, out var encodedLength);

                var afterLengthBytes = start.Slice(encodedLength);
                var payload = start.Slice(4, payloadLength);

                payload.CopyTo(afterLengthBytes);

                bytes = start.Slice(encodedLength + payloadLength);
            }
        }

        public readonly ref struct CursorWritingContext
        {
            private readonly MemoryCursor cursor;
            private readonly int startPacketOffset;
            private readonly int toWriteLengthOffset;

            public CursorWritingContext(
                MemoryCursor cursor, 
                int startPacketOffset,
                int toWriteLengthOffset)
            {
                this.cursor = cursor;
                this.startPacketOffset = startPacketOffset;
                this.toWriteLengthOffset = toWriteLengthOffset;
            }

            public void Dispose()
            {
                var packetLength = cursor - startPacketOffset;
                var payloadLength = cursor - toWriteLengthOffset;
                var payload = cursor.Move(-payloadLength);

                Span<byte> payloadBuffer = stackalloc byte[payloadLength];

                payload.Span.CopyTo(payloadBuffer);
                cursor.EncodeVariable32(packetLength);
                payloadBuffer.CopyTo(cursor);
            }
        }
    }
}
