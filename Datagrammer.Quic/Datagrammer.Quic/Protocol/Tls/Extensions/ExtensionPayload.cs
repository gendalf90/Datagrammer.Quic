using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class ExtensionPayload
    {
        public static ReadOnlyMemory<byte> Slice(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> afterPayloadBytes)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var payloadLengthBytes = bytes.Slice(0, 2);
            var payloadLength = (int)NetworkBitConverter.ParseUnaligned(payloadLengthBytes.Span);

            if(bytes.Length < payloadLength + 2)
            {
                throw new EncodingException();
            }

            afterPayloadBytes = bytes.Slice(payloadLength + 2);

            return bytes.Slice(2, payloadLength);
        }

        public static WritingContext StartWriting(ref Span<byte> bytes)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var context = new WritingContext(bytes);

            bytes = bytes.Slice(2);

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

                if (payloadLength > ushort.MaxValue)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(start, (ulong)payloadLength, 2);
            }
        }
    }
}
