using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IAead : IDisposable
    {
        CryptoToken StartEncryption(ReadOnlySpan<byte> data, Span<byte> destination);

        CryptoToken StartDecryption(ReadOnlySpan<byte> data, Span<byte> destination);

        void Finish(CryptoToken token);
    }
}
