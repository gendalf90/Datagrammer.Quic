using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface IHash
    {
        ValueBuffer CreateHash(ReadOnlySpan<byte> bytes);

        ValueBuffer CreateHandshakeSecret(ValueBuffer sharedSecret);

        ValueBuffer CreateClientHandshakeTrafficSecret(ValueBuffer handshakeSecret, ValueBuffer helloHash);

        ValueBuffer CreateServerHandshakeTrafficSecret(ValueBuffer handshakeSecret, ValueBuffer helloHash);

        ValueBuffer CreateKey(ValueBuffer trafficSecret);

        ValueBuffer CreateIv(ValueBuffer trafficSecret);

        ValueBuffer CreateVerifyData(ValueBuffer secret, ValueBuffer finishedHash);

        ValueBuffer CreateMasterSecret(ValueBuffer secret);

        ValueBuffer CreateClientApplicationTrafficSecret(ValueBuffer masterSecret, ValueBuffer handshakeHash);

        ValueBuffer CreateServerApplicationTrafficSecret(ValueBuffer masterSecret, ValueBuffer handshakeHash);
    }
}
