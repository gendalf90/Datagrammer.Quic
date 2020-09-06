using System;
using System.Security.Cryptography;
using System.Text;

namespace Datagrammer.Quic.Protocol.Tls
{
    public class Hash
    {
        private const int KeySize = 16;
        private const int IvSize = 12;
        private const int LabelMaxSize = 528;
        private const string HmacPrefix = "HMAC";

        private static readonly byte[] FinishedLabel = Encoding.ASCII.GetBytes("tls13 finished");
        private static readonly byte[] DerivedLabel = Encoding.ASCII.GetBytes("tls13 derived");
        private static readonly byte[] ClientHandshakeTrafficLabel = Encoding.ASCII.GetBytes("tls13 c hs traffic");
        private static readonly byte[] ServerHandshakeTrafficLabel = Encoding.ASCII.GetBytes("tls13 s hs traffic");
        private static readonly byte[] KeyLabel = Encoding.ASCII.GetBytes("tls13 key");
        private static readonly byte[] IvLabel = Encoding.ASCII.GetBytes("tls13 iv");

        private readonly string hmacName;
        private readonly string name;
        private readonly int length;
        private readonly byte[] handshakeDerivedSecret;

        private Hash(HashAlgorithmName algorithmName)
        {
            name = algorithmName.Name;
            hmacName = HmacPrefix + algorithmName.Name;
            length = KeyedHashAlgorithm.Create(hmacName).HashSize / 8;
            handshakeDerivedSecret = ComputeHandshakeDerivedSecret();
        }

        private byte[] ComputeHandshakeDerivedSecret()
        {
            var earlySecret = HkdfExtract(new byte[length], new byte[length]);
            var emptyHash = ComputeHash(ReadOnlyMemory<byte>.Empty).ToArray();

            return HkdfExpandLabel(earlySecret, DerivedLabel, emptyHash, length);
        }

        public static Hash Sha256 { get; } = new Hash(HashAlgorithmName.SHA256);

        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> bytes)
        {
            using (var currentAlgorithm = HashAlgorithm.Create(name))
            {
                return currentAlgorithm.ComputeHash(bytes.ToArray());
            }
        }

        public ReadOnlyMemory<byte> CreateHandshakeSecret(ReadOnlyMemory<byte> sharedSecret)
        {
            return HkdfExtract(handshakeDerivedSecret, sharedSecret.ToArray());
        }

        public ReadOnlyMemory<byte> CreateClientHandshakeTrafficSecret(ReadOnlyMemory<byte> handshakeSecret, ReadOnlyMemory<byte> helloHash)
        {
            return HkdfExpandLabel(handshakeSecret.ToArray(), ClientHandshakeTrafficLabel, helloHash.ToArray(), length);
        }

        public ReadOnlyMemory<byte> CreateServerHandshakeTrafficSecret(ReadOnlyMemory<byte> handshakeSecret, ReadOnlyMemory<byte> helloHash)
        {
            return HkdfExpandLabel(handshakeSecret.ToArray(), ServerHandshakeTrafficLabel, helloHash.ToArray(), length);
        }

        public ReadOnlyMemory<byte> CreateHandshakeKey(ReadOnlyMemory<byte> handshakeTrafficSecret)
        {
            return HkdfExpandLabel(handshakeTrafficSecret.ToArray(), KeyLabel, Array.Empty<byte>(), KeySize);
        }

        public ReadOnlyMemory<byte> CreateHandshakeIv(ReadOnlyMemory<byte> handshakeTrafficSecret)
        {
            return HkdfExpandLabel(handshakeTrafficSecret.ToArray(), IvLabel, Array.Empty<byte>(), IvSize);
        }

        public ReadOnlyMemory<byte> CreateVerifyData(ReadOnlyMemory<byte> secret, ReadOnlyMemory<byte> finishedHash)
        {
            return HkdfExtract(HkdfExpandLabel(secret.ToArray(), FinishedLabel, Array.Empty<byte>(), length), finishedHash.ToArray());
        }

        private byte[] HkdfExpandLabel(byte[] secret, byte[] label, byte[] context, int length)
        {
            return HkdfExpand(secret, CreateHkdfLabel(label, context, length), length);
        }

        private byte[] HkdfExpand(byte[] prk, byte[] info, int outputLength)
        {
            var resultBlock = new byte[0];
            var result = new byte[outputLength];
            var bytesRemaining = outputLength;

            for (int i = 1; bytesRemaining > 0; i++)
            {
                var currentInfo = new byte[resultBlock.Length + info.Length + 1];
                Array.Copy(resultBlock, 0, currentInfo, 0, resultBlock.Length);
                Array.Copy(info, 0, currentInfo, resultBlock.Length, info.Length);
                currentInfo[currentInfo.Length - 1] = (byte)i;
                resultBlock = HkdfExtract(prk, currentInfo);
                Array.Copy(resultBlock, 0, result, outputLength - bytesRemaining, Math.Min(resultBlock.Length, bytesRemaining));
                bytesRemaining -= resultBlock.Length;
            }

            return result;
        }

        private byte[] HkdfExtract(byte[] key, byte[] data)
        {
            using (var currentAlgorithm = KeyedHashAlgorithm.Create(hmacName))
            {
                currentAlgorithm.Key = key;

                return currentAlgorithm.ComputeHash(data);
            }
        }

        private byte[] CreateHkdfLabel(byte[] label, byte[] context, int length)
        {
            var buffer = new byte[LabelMaxSize];
            var remainings = buffer.AsSpan();

            WriteLength(ref remainings, length);
            WriteLabel(ref remainings, label);
            WriteContext(ref remainings, context);

            Array.Resize(ref buffer, buffer.Length - remainings.Length);

            return buffer;
        }

        private void WriteLength(ref Span<byte> bytes, int length)
        {
            var lengthWrittenBytes = NetworkBitConverter.WriteUnaligned(bytes, (ulong)length, 2);

            bytes = bytes.Slice(lengthWrittenBytes);
        }

        private void WriteLabel(ref Span<byte> bytes, ReadOnlySpan<byte> label)
        {
            var vectorContext = ByteVector.StartVectorWriting(ref bytes, 0..255);

            label.CopyTo(bytes);

            bytes = bytes.Slice(label.Length);

            vectorContext.Complete(ref bytes);
        }

        private static void WriteContext(ref Span<byte> bytes, ReadOnlySpan<byte> context)
        {
            var vectorContext = ByteVector.StartVectorWriting(ref bytes, 0..255);

            context.CopyTo(bytes);

            bytes = bytes.Slice(context.Length);

            vectorContext.Complete(ref bytes);
        }
    }
}
