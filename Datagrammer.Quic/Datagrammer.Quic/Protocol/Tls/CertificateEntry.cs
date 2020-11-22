using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct CertificateEntry
    {
        public CertificateEntry(MemoryBuffer data)
        {
            Data = data;
        }

        public MemoryBuffer Data { get; }

        public static CertificateEntry Parse(MemoryCursor cursor)
        {
            var data = ByteVector.SliceVectorBytes(cursor, 1..ByteVector.MaxUInt24);

            ByteVector.SliceVectorBytes(cursor, 0..ushort.MaxValue);

            return new CertificateEntry(data);
        }

        //public static CertificateEntry Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        //{
        //    var data = ByteVector.SliceVectorBytes(bytes, 1..ByteVector.MaxUInt24, out var afterDataBytes);

        //    ByteVector.SliceVectorBytes(afterDataBytes, 0..ushort.MaxValue, out var afterExtensionsBytes);

        //    remainings = afterExtensionsBytes;

        //    return new CertificateEntry(data);
        //}

        //public void Write(ref Span<byte> destination)
        //{
        //    var context = ByteVector.StartVectorWriting(ref destination, 1..ByteVector.MaxUInt24);

        //    if(!Data.Span.TryCopyTo(destination))
        //    {
        //        throw new EncodingException();
        //    }

        //    destination = destination.Slice(Data.Length);

        //    context.Complete(ref destination);

        //    ByteVector
        //        .StartVectorWriting(ref destination, 0..ushort.MaxValue)
        //        .Complete(ref destination);
        //}

        public static void Write(ReadOnlyMemory<byte> data, MemoryCursor cursor)
        {
            using (ByteVector.StartVectorWriting(cursor, 1..ByteVector.MaxUInt24))
            {
                data.CopyTo(cursor);
            }

            ByteVector
                .StartVectorWriting(cursor, 0..ushort.MaxValue)
                .Dispose();
        }
    }
}
