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

        public static EcnCounts Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            remainings = ReadOnlyMemory<byte>.Empty;

            var ect0 = VariableLengthEncoding.Decode(bytes.Span, out int decodedLength);
            var afterEct0Bytes = bytes.Slice(decodedLength);
            var ect1 = VariableLengthEncoding.Decode(afterEct0Bytes.Span, out decodedLength);
            var afterEct1Bytes = afterEct0Bytes.Slice(decodedLength);
            var ce = VariableLengthEncoding.Decode(afterEct1Bytes.Span, out decodedLength);
            var afterCeBytes = afterEct1Bytes.Slice(decodedLength);

            remainings = afterCeBytes;

            return new EcnCounts(ect0, ect1, ce);
        }
    }
}
