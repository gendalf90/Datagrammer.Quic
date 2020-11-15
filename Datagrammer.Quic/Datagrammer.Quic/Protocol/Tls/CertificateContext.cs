using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class CertificateContext
    {
        public static void SkipBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            ByteVector.SliceVectorBytes(bytes, 0..byte.MaxValue, out remainings);
        }

        public static void WriteEmpty(ref Span<byte> destination)
        {
            ByteVector
                .StartVectorWriting(ref destination, 0..byte.MaxValue)
                .Complete(ref destination);
        }

        public static void WriteEmpty(MemoryCursor cursor)
        {
            ByteVector
                .StartVectorWriting(cursor, 0..byte.MaxValue)
                .Dispose();
        }
    }
}
