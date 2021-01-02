using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IPublicCertificate : IDisposable
    {
        bool VerifyHash(ValueBuffer hash, ReadOnlySpan<byte> signature);
    }
}
