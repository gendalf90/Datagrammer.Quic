using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface ICipher : IDisposable
    {
        ValueBuffer CreateMask(ReadOnlySpan<byte> sample);
    }
}
