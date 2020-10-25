using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IPrivateCertificate : IDisposable
    {
        void WritePublic(ref Span<byte> destination);

        void SignHash(ReadOnlyMemory<byte> hash, ref Span<byte> destination);
    }
}
