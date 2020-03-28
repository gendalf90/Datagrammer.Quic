using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketNumber
    {
        internal PacketNumber(ulong number)
        {
            Number = number;
        }

        public ulong Number { get; }

        public static PacketNumber Parse32(ReadOnlyMemory<byte> bytes)
        {
            if (bytes.IsEmpty || bytes.Length > 4)
            {
                throw new EncodingException();
            }

            var value = NetworkBitConverter.ToUInt32(bytes.Span);

            return new PacketNumber(value);
        }

        public static PacketNumber Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var value = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return new PacketNumber(value);
        }
    }
}
