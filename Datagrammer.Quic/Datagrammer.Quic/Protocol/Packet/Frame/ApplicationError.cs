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

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out ApplicationError error, out ReadOnlyMemory<byte> remainings)
        {
            error = new ApplicationError();
            remainings = ReadOnlyMemory<byte>.Empty;

            if (!VariableLengthEncoding.TryDecode(bytes.Span, out var id, out var decodedLength))
            {
                return false;
            }

            error = new ApplicationError(id);
            remainings = bytes.Slice(decodedLength);

            return true;
        }
    }
}
