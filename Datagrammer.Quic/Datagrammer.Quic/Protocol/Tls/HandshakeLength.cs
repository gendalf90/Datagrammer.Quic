using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class HandshakeLength
    {
        public static ReadOnlyMemory<byte> SliceHandshakeBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> afterHandshakeBytes)
        {
            if(bytes.Length < 3)
            {
                throw new EncodingException();
            }

            var lengthBytes = bytes.Slice(0, 3);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);
            var afterLengthBytes = bytes.Slice(3);

            if (afterLengthBytes.Length < length)
            {
                throw new EncodingException();
            }

            afterHandshakeBytes = afterLengthBytes.Slice(length);

            return afterLengthBytes.Slice(0, length);
        }

        public static WritingContext StartHandshakeWriting(Span<byte> destination)
        {
            return WritingContext.Initialize(destination, 3);
        }

        public static int FinishHandshakeWriting(WritingContext context)
        {
            if (context.Length < 3)
            {
                throw new EncodingException();
            }

            var length = context.Length - 3;

            if (length > ushort.MaxValue)
            {
                throw new EncodingException();
            }

            NetworkBitConverter.WriteUnaligned(context.Initial, (ulong)length, 3);

            return context.Length;
        }
    }
}
