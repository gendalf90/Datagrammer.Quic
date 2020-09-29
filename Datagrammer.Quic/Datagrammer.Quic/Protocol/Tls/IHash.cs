using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IHash
    {
        ReadOnlyMemory<byte> CreateHash(ReadOnlyMemory<byte> bytes);

        ReadOnlyMemory<byte> CreateHandshakeSecret(ReadOnlyMemory<byte> sharedSecret);

        ReadOnlyMemory<byte> CreateClientHandshakeTrafficSecret(ReadOnlyMemory<byte> handshakeSecret, ReadOnlyMemory<byte> helloHash);

        ReadOnlyMemory<byte> CreateServerHandshakeTrafficSecret(ReadOnlyMemory<byte> handshakeSecret, ReadOnlyMemory<byte> helloHash);

        ReadOnlyMemory<byte> CreateHandshakeKey(ReadOnlyMemory<byte> handshakeTrafficSecret);

        ReadOnlyMemory<byte> CreateHandshakeIv(ReadOnlyMemory<byte> handshakeTrafficSecret);

        ReadOnlyMemory<byte> CreateVerifyData(ReadOnlyMemory<byte> secret, ReadOnlyMemory<byte> finishedHash);
    }
}
