using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public static class PacketLength
    {
        public static bool CheckPacketLength(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> packetRemainingBytes, out ReadOnlyMemory<byte> afterPacketRemainings)
        {
            packetRemainingBytes = ReadOnlyMemory<byte>.Empty;
            afterPacketRemainings = ReadOnlyMemory<byte>.Empty;

            if (!VariableLengthEncoding.TryDecode32(bytes.Span, out var length, out var decodedBytesLength))
            {
                return false;
            }

            var afterLengthBytes = bytes.Slice(decodedBytesLength);

            if(afterLengthBytes.Length < length)
            {
                return false;
            }

            packetRemainingBytes = afterLengthBytes.Slice(0, length);
            afterPacketRemainings = afterLengthBytes.Slice(length);

            return true;
        }
    }
}
