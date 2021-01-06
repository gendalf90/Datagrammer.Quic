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

        public TimeSpan GetDelay(int exponent = DefaultExponent)
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

        public static AckDelay CreateDelay(TimeSpan timeSpan, int exponent = DefaultExponent)
        {
            if (exponent < 0 || exponent > MaxExponent)
            {
                throw new EncodingException();
            }

            var exponentMultiplicator = (long)Math.Pow(2, exponent);
            var ticks = timeSpan.Ticks;
            var microseconds = ticks / 10;
            var value = microseconds / exponentMultiplicator;

            return new AckDelay(value);
        }

        public static AckDelay Parse(MemoryCursor cursor)
        {
            var delay = cursor.DecodeVariable64();

            return new AckDelay(delay);
        }

        public void Write(MemoryCursor cursor)
        {
            cursor.EncodeVariable64(value);
        }
    }
}
