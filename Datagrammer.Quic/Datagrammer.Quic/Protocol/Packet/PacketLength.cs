using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public static class PacketLength
    {
        public static void CheckPacketLength(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> packetBytes, out ReadOnlyMemory<byte> afterPacketBytes)
        {
            packetBytes = ReadOnlyMemory<byte>.Empty;
            afterPacketBytes = ReadOnlyMemory<byte>.Empty;

            var length = VariableLengthEncoding.Decode32(bytes.Span, out var decodedBytesLength);
            var afterLengthBytes = bytes.Slice(decodedBytesLength);

            if(afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            packetBytes = afterLengthBytes.Slice(0, length);
            afterPacketBytes = afterLengthBytes.Slice(length);
        }
    }
}
