using Datagrammer.Quic.Protocol.Error;
using System;
using System.Transactions;

namespace Datagrammer.Quic.Protocol.Packet
{
    public static class PacketLength
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
            if(bytes.Length < 4)
            {
                throw new EncodingException();
            }

            return WritingContext.Initialize(bytes).Move(4);
        }

        public static void FinishPacketWriting(WritingContext context, out Span<byte> remainings)
        {
            if(context.Length < 4)
            {
                throw new EncodingException();
            }

            var payloadLength = context.Length - 4;

            VariableLengthEncoding.Encode(context.Initial, (ulong)payloadLength, out var encodedLength);

            var afterLengthBytes = context.Initial.Slice(encodedLength);
            var payload = context.Initial.Slice(4, payloadLength);

            payload.CopyTo(afterLengthBytes);

            remainings = context.Initial.Slice(encodedLength + payloadLength);
        }
    }
}
