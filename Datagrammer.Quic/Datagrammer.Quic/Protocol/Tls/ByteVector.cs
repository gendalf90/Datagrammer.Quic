using Datagrammer.Quic.Protocol.Error;
using System;
using System.IO;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class ByteVector
    {
        public static int MaxUInt24 = 0xffffff;

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

        public static void WriteVector(Stream stream, Range range, ReadOnlyMemory<byte> bytes)
        {
            var lengthSizeInBytes = NetworkBitConverter.GetByteLength((ulong)range.End.Value);

            if (bytes.Length < range.Start.Value || bytes.Length > range.End.Value)
            {
                throw new EncodingException();
            }

            NetworkBitConverter.WriteUnaligned(stream, (ulong)bytes.Length, lengthSizeInBytes);

            stream.Write(bytes.Span);
        }

        public static WritingContext StartVectorWriting(ref Span<byte> bytes, Range range)
        {
            var context = new WritingContext(bytes, range);
            var lengthSizeInBytes = NetworkBitConverter.GetByteLength((ulong)range.End.Value);

            if(bytes.Length < lengthSizeInBytes)
            {
                throw new EncodingException();
            }

            bytes = bytes.Slice(lengthSizeInBytes);

            return context;
        }

        public readonly ref struct WritingContext
        {
            private readonly Span<byte> start;
            private readonly Range range;

            public WritingContext(Span<byte> start, Range range)
            {
                this.start = start;
                this.range = range;
            }

            public void Complete(ref Span<byte> bytes)
            {
                var offset = start.Length - bytes.Length;
                var lengthSizeInBytes = NetworkBitConverter.GetByteLength((ulong)range.End.Value);

                if (offset < lengthSizeInBytes)
                {
                    throw new EncodingException();
                }

                var payloadLength = offset - lengthSizeInBytes;

                if (payloadLength < range.Start.Value || payloadLength > range.End.Value)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(start, (ulong)payloadLength, lengthSizeInBytes);
            }
        }
    }
}
