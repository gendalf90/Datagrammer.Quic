using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface ICipher : IDisposable
    {
        int CreateMask(ReadOnlySpan<byte> sample, Span<byte> destination);
    }
}
