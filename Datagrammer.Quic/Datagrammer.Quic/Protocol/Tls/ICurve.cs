using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface ICurve
    {
        ReadOnlyMemory<byte> GeneratePrivateKey();

        ReadOnlyMemory<byte> GeneratePublicKey(ReadOnlySpan<byte> privateKey);

        ReadOnlyMemory<byte> GenerateSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey);
    }
}
