using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class ApplicationLength
    {
        private const int MaxLength = 0x4000;

        public static ReadOnlyMemory<byte> SliceApplicationBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> afterApplicationBytes)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var lengthBytes = bytes.Slice(0, 2);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);
            var afterLengthBytes = bytes.Slice(2);

            if (afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            afterApplicationBytes = afterLengthBytes.Slice(length);

            return afterLengthBytes.Slice(0, length);
        }

        public static WritingContext StartWriting(ref Span<byte> destination)
        {
            if (destination.Length < 2)
            {
                throw new EncodingException();
            }

            var context = new WritingContext(destination);

            destination = destination.Slice(2);

            return context;
        }

        public readonly ref struct WritingContext
        {
            private readonly Span<byte> start;

            public WritingContext(Span<byte> start)
            {
                this.start = start;
            }

            public void Complete(ref Span<byte> bytes)
            {
                var offset = start.Length - bytes.Length;

                if (offset < 2)
                {
                    throw new EncodingException();
                }

                var payloadLength = offset - 2;

                if (payloadLength > MaxLength)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(start, (ulong)payloadLength, 2);
            }
        }
    }
}
