using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol
{
    public readonly ref struct WritingContext
    {
        private WritingContext(Span<byte> initial, Span<byte> current, int length)
        {
            Initial = initial;
            Current = current;
            Length = length;
        }

        public Span<byte> Initial { get; }

        public Span<byte> Current { get; }

        public int Length { get; }

        public WritingContext Move(int length)
        {
            if(length > Current.Length || length < 0)
            {
                throw new EncodingException();
            }

            return new WritingContext(Initial, Current.Slice(length), Length + length);
        }

        public static WritingContext Initialize(Span<byte> initial)
        {
            return new WritingContext(initial, initial, 0);
        }
    }
}
