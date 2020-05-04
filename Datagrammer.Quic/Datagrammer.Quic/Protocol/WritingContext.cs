using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol
{
    public ref struct WritingContext
    {
        private WritingContext(Span<byte> initial, Span<byte> current, int length)
        {
            Initial = initial;
            Current = current;
            Length = length;
        }

        public Span<byte> Initial { get; private set; }

        public Span<byte> Current { get; private set; }

        public int Length { get; private set; }

        public void Move(int length)
        {
            if(length > Current.Length || length < 0)
            {
                throw new EncodingException();
            }

            Current = Current.Slice(length);
            Length += length;
        }

        public static WritingContext Initialize(Span<byte> initial)
        {
            return new WritingContext(initial, initial, 0);
        }

        public static WritingContext Initialize(Span<byte> initial, int length)
        {
            var context = Initialize(initial);

            context.Move(length);

            return context;
        }
    }
}
