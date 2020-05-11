using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol
{
    public readonly ref struct WritingContext
    {
        public WritingContext(Span<byte> start, Span<byte> remainings, int length)
        {
            Start = start;
            Remainings = remainings;
            Length = length;
        }

        public WritingContext(Span<byte> start)
        {
            Start = start;
            Remainings = start;
            Length = 0;
        }

        public Span<byte> Start { get; }

        public Span<byte> Remainings { get; }

        public int Length { get; }
    }

    public static class WritingContextExtensions
    {
        public static void Move(this ref WritingContext context, int length)
        {
            if (length > context.Remainings.Length || length < 0)
            {
                throw new EncodingException();
            }

            context = new WritingContext(context.Start, context.Remainings.Slice(length), context.Length + length);
        }

        public static void Write(this ref WritingContext context, ReadOnlySpan<byte> bytes)
        {
            if(!bytes.TryCopyTo(context.Remainings))
            {
                throw new EncodingException();
            }

            context = new WritingContext(context.Start, context.Remainings.Slice(bytes.Length), context.Length + bytes.Length);
        }
    }
}
