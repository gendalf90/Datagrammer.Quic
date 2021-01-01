namespace Datagrammer.Quic.Protocol.Tls
{
    public interface ICurve
    {
        ValueBuffer GeneratePrivateKey();

        ValueBuffer GeneratePublicKey(ValueBuffer privateKey);

        ValueBuffer GenerateSharedSecret(ValueBuffer privateKey, ValueBuffer publicKey);
    }
}
