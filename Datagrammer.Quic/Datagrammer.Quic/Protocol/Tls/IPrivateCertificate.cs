using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IPrivateCertificate : IDisposable
    {
        void WritePublic(MemoryCursor cursor);

        void SignHash(ValueBuffer hash, MemoryCursor cursor);
    }
}
