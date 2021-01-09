using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public interface ISignatureHash
    {
        ValueBuffer CreateHash(ReadOnlySpan<byte> bytes);

        ValueBuffer CreateVerifyData(ValueBuffer secret, ValueBuffer finishedHash);
    }
}
