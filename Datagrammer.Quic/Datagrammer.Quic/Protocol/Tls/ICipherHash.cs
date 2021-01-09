using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface ICipherHash
    {
        ValueBuffer CreateHash(ReadOnlySpan<byte> bytes);

        (ValueBuffer HandshakeSecret, ValueBuffer TrafficSecret, ValueBuffer Key, ValueBuffer Iv) CreateClientHandshakeSecrets(ValueBuffer sharedSecret, ValueBuffer helloHash);

        (ValueBuffer HandshakeSecret, ValueBuffer TrafficSecret, ValueBuffer Key, ValueBuffer Iv) CreateServerHandshakeSecrets(ValueBuffer sharedSecret, ValueBuffer helloHash);

        (ValueBuffer MasterSecret, ValueBuffer TrafficSecret, ValueBuffer Key, ValueBuffer Iv) CreateClientApplicationSecrets(ValueBuffer handshakeSecret, ValueBuffer handshakeHash);

        (ValueBuffer MasterSecret, ValueBuffer TrafficSecret, ValueBuffer Key, ValueBuffer Iv) CreateServerApplicationSecrets(ValueBuffer handshakeSecret, ValueBuffer handshakeHash);

        (ValueBuffer Key, ValueBuffer Iv, ValueBuffer Hp) CreateClientInitialSecrets(ReadOnlySpan<byte> cid);

        (ValueBuffer Key, ValueBuffer Iv, ValueBuffer Hp) CreateServerInitialSecrets(ReadOnlySpan<byte> cid);

        (ValueBuffer Key, ValueBuffer Iv, ValueBuffer Hp, ValueBuffer Ku) CreatePacketSecrets(ValueBuffer secret);
    }
}
