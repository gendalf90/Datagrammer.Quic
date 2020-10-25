using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IPublicCertificate : IDisposable
    {
        bool VerifyHash(ReadOnlyMemory<byte> hash, ReadOnlyMemory<byte> signature);
    }
}
