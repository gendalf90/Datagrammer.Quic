using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IAead : IDisposable
    {
        CryptingToken StartEncrypting(ReadOnlySpan<byte> data, MemoryCursor cursor);

        CryptingToken StartDecrypting(ReadOnlySpan<byte> data, MemoryCursor cursor);

        void Finish(CryptingToken token);
    }
}
