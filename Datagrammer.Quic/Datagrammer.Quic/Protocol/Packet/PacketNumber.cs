using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketNumber
    {
        private readonly ulong value;

        public PacketNumber(ulong value)
        {
            this.value = value;
        }

        public static bool TryParse32(ReadOnlyMemory<byte> bytes, out PacketNumber packetNumber)
        {
            packetNumber = new PacketNumber();

            if (bytes.IsEmpty || bytes.Length > 4)
            {
                return false;
            }

            var value = NetworkBitConverter.ToUInt32(bytes.Span);

            packetNumber = new PacketNumber(value);

            return true;
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out PacketNumber packetNumber, out ReadOnlyMemory<byte> remainings)
        {
            packetNumber = new PacketNumber();
            remainings = ReadOnlyMemory<byte>.Empty;

            if(!VariableLengthEncoding.TryDecode(bytes.Span, out var value, out var decodedLength))
            {
                return false;
            }

            packetNumber = new PacketNumber(value);
            remainings = bytes.Slice(decodedLength);

            return true;
        }
    }
}
