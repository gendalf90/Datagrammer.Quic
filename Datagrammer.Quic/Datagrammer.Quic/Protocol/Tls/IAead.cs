using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IAead : IDisposable
    {
        void Encrypt(ReadOnlySpan<byte> data, int seq, ref Span<byte> destination);

        void Decrypt(ReadOnlySpan<byte> data, int seq, ref Span<byte> destination);
    }
}
