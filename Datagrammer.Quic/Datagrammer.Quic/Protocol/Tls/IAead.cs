using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IAead : IDisposable
    {
        int TagLength { get; }

        void Encrypt(Span<byte> data, Span<byte> tag, ulong sequenceNumber, ReadOnlySpan<byte> associatedData);

        void Decrypt(Span<byte> data, ReadOnlySpan<byte> tag, ulong sequenceNumber, ReadOnlySpan<byte> associatedData);
    }
}
