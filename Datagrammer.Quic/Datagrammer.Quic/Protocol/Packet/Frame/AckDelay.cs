using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct AckDelay
    {
        private const int MaxExponent = 20;
        private const int DefaultExponent = 3;

        private readonly long value;

        private AckDelay(long value)
        {
            this.value = value;
        }

        public TimeSpan GetDelayByDefault()
        {
            return GetDelayByExponent(DefaultExponent);
        }

        public TimeSpan GetDelayByExponent(int exponent)
        {
            if(exponent < 0 || exponent > MaxExponent)
            {
                throw new EncodingException();
            }

            var exponentMultiplicator = (long)Math.Pow(2, exponent);
            var microseconds = value * exponentMultiplicator;
            var ticks = microseconds * 10;

            return TimeSpan.FromTicks(ticks);
        }

        public static AckDelay Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var delay = VariableLengthEncoding.Decode64(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return new AckDelay(delay);
        }
    }
}
