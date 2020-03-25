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

        public bool TryGetDelayByExponent(int exponent, out TimeSpan delay)
        {
            delay = new TimeSpan();

            if(exponent < 0 || exponent > MaxExponent)
            {
                return false;
            }

            delay = GetDelayByExponent(exponent);

            return true;
        }

        private TimeSpan GetDelayByExponent(int exponent)
        {
            var exponentMultiplicator = (long)Math.Pow(2, exponent);
            var microseconds = value * exponentMultiplicator;
            var ticks = microseconds * 10;

            return TimeSpan.FromTicks(ticks);
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out AckDelay result, out ReadOnlyMemory<byte> remainings)
        {
            result = new AckDelay();
            remainings = ReadOnlyMemory<byte>.Empty;

            if(!VariableLengthEncoding.TryDecode64(bytes.Span, out var delay, out var decodedLength))
            {
                return false;
            }

            result = new AckDelay(delay);
            remainings = bytes.Slice(decodedLength);

            return true;
        }
    }
}
