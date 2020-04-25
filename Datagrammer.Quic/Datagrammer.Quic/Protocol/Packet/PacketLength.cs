using Datagrammer.Quic.Protocol.Error;
using System;

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

        public static void WritePacketBytes(Span<byte> bytes, PacketNumber packetNumber, ReadOnlyMemory<byte> payload, out Span<byte> remainings)
        {
            var length = packetNumber.GetLength() + payload.Length;
            
            VariableLengthEncoding.Encode(bytes, (ulong)length, out var encodedLength);

            var afterLengthBytes = bytes.Slice(encodedLength);

            if(afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            packetNumber.Write(afterLengthBytes, out var afterPacketNumberBytes);
            payload.Span.CopyTo(afterPacketNumberBytes);

            remainings = afterLengthBytes.Slice(length);
        }
    }
}
