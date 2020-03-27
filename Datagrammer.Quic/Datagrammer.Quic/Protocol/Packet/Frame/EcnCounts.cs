using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct EcnCounts
    {
        private EcnCounts(ulong ect0, ulong ect1, ulong ce)
        {
            Ect0 = ect0;
            Ect1 = ect1;
            Ce = ce;
        }

        public ulong Ect0 { get; }

        public ulong Ect1 { get; }

        public ulong Ce { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out EcnCounts result, out ReadOnlyMemory<byte> remainings)
        {
            result = new EcnCounts();
            remainings = ReadOnlyMemory<byte>.Empty;

            if(!VariableLengthEncoding.TryDecode(bytes.Span, out var ect0, out int decodedLength))
            {
                return false;
            }

            var afterEct0Bytes = bytes.Slice(decodedLength);

            if (!VariableLengthEncoding.TryDecode(afterEct0Bytes.Span, out var ect1, out decodedLength))
            {
                return false;
            }

            var afterEct1Bytes = afterEct0Bytes.Slice(decodedLength);

            if (!VariableLengthEncoding.TryDecode(afterEct1Bytes.Span, out var ce, out decodedLength))
            {
                return false;
            }

            var afterCeBytes = afterEct1Bytes.Slice(decodedLength);

            result = new EcnCounts(ect0, ect1, ce);
            remainings = afterCeBytes;

            return true;
        }
    }
}
