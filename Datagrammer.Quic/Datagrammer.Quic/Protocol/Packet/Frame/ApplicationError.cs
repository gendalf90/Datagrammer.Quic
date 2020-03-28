using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct ApplicationError
    {
        private readonly ulong value;

        private ApplicationError(ulong value)
        {
            this.value = value;
        }

        public static ApplicationError Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var id = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return new ApplicationError(id);
        }
    }
}
