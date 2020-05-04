using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class ByteVector
    {
        public static ReadOnlyMemory<byte> SliceVectorBytes(ReadOnlyMemory<byte> data, Range range, out ReadOnlyMemory<byte> remainings)
        {
            var lengthSizeInBytes = NetworkBitConverter.GetByteLength((ulong)range.End.Value);

            if(data.Length < lengthSizeInBytes || lengthSizeInBytes > 4)
            {
                throw new EncodingException();
            }

            var lengthBytes = data.Slice(0, lengthSizeInBytes);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);
            var afterLengthBytes = data.Slice(lengthSizeInBytes);

            if(afterLengthBytes.Length < length || length < range.Start.Value || length > range.End.Value)
            {
                throw new EncodingException();
            }

            remainings = afterLengthBytes.Slice(length);

            return afterLengthBytes.Slice(0, length);
        }

        public static WritingContext StartVectorWriting(Span<byte> bytes)
        {
            if (bytes.Length < 4)
            {
                throw new EncodingException();
            }

            return WritingContext.Initialize(bytes).Move(4);
        }

        public static int FinishVectorWriting(WritingContext context, Range range)
        {
            if (context.Length < 4)
            {
                throw new EncodingException();
            }

            var payloadLength = context.Length - 4;

            if(payloadLength < range.Start.Value || payloadLength > range.End.Value)
            {
                throw new EncodingException();
            }

            var lengthSizeInBytes = NetworkBitConverter.GetByteLength((ulong)range.End.Value);

            NetworkBitConverter.WriteUnaligned(context.Initial, (ulong)payloadLength, lengthSizeInBytes);

            var afterLengthBytes = context.Initial.Slice(lengthSizeInBytes);
            var payload = context.Initial.Slice(4, payloadLength);

            payload.CopyTo(afterLengthBytes);

            return lengthSizeInBytes + payloadLength;
        }
    }
}
