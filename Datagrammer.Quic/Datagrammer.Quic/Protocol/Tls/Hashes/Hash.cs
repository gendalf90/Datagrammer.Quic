using Datagrammer.Quic.Protocol.Error;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Datagrammer.Quic.Protocol.Tls.Hashes
{
    public class Hash : IHash
    {
        private const int KeySize = 16;
        private const int IvSize = 12;
        private const int LabelMaxSize = 528;

        private static readonly byte[] FinishedLabel = Encoding.ASCII.GetBytes("tls13 finished");
        private static readonly byte[] DerivedLabel = Encoding.ASCII.GetBytes("tls13 derived");
        private static readonly byte[] ClientHandshakeTrafficLabel = Encoding.ASCII.GetBytes("tls13 c hs traffic");
        private static readonly byte[] ServerHandshakeTrafficLabel = Encoding.ASCII.GetBytes("tls13 s hs traffic");
        private static readonly byte[] KeyLabel = Encoding.ASCII.GetBytes("tls13 key");
        private static readonly byte[] IvLabel = Encoding.ASCII.GetBytes("tls13 iv");

        private readonly HashAlgorithmName algorithmName;

        private readonly byte[] derivedSecret;

        private Hash(HashAlgorithmName algorithmName)
        {
            this.algorithmName = algorithmName;

            derivedSecret = ComputeDerivedSecret();
        }

        private byte[] ComputeDerivedSecret()
        {
            var emptyBuffer = new byte[HashLength];
            var earlySecretBuffer = new byte[HashLength];
            var derivedSecretBuffer = new byte[HashLength];

            HkdfExtract(emptyBuffer, emptyBuffer, earlySecretBuffer);

            var emptyHash = CreateHash(ReadOnlyMemory<byte>.Empty);

            HkdfExpandLabel(earlySecretBuffer, DerivedLabel, emptyHash.Span, derivedSecretBuffer);

            return derivedSecretBuffer;
        }

        public static Hash Sha256 { get; } = new Hash(HashAlgorithmName.SHA256);

        public ReadOnlyMemory<byte> CreateHash(ReadOnlyMemory<byte> bytes)
        {
            using var algorithm = IncrementalHash.CreateHash(algorithmName);

            var buffer = new byte[HashLength];

            HkdfExtract(algorithm, bytes.Span, buffer);

            return buffer;
        }

        public ReadOnlyMemory<byte> CreateHandshakeSecret(ReadOnlyMemory<byte> sharedSecret)
        {
            var resultBuffer = new byte[HashLength];

            HkdfExtract(derivedSecret, sharedSecret.Span, resultBuffer);

            return resultBuffer;
        }

        public ReadOnlyMemory<byte> CreateClientHandshakeTrafficSecret(ReadOnlyMemory<byte> handshakeSecret, ReadOnlyMemory<byte> helloHash)
        {
            var resultBuffer = new byte[HashLength];

            HkdfExpandLabel(handshakeSecret.ToArray(), ClientHandshakeTrafficLabel, helloHash.Span, resultBuffer);

            return resultBuffer;
        }

        public ReadOnlyMemory<byte> CreateServerHandshakeTrafficSecret(ReadOnlyMemory<byte> handshakeSecret, ReadOnlyMemory<byte> helloHash)
        {
            var resultBuffer = new byte[HashLength];

            HkdfExpandLabel(handshakeSecret.ToArray(), ServerHandshakeTrafficLabel, helloHash.Span, resultBuffer);

            return resultBuffer;
        }

        public ReadOnlyMemory<byte> CreateHandshakeKey(ReadOnlyMemory<byte> handshakeTrafficSecret)
        {
            var resultBuffer = new byte[KeySize];

            HkdfExpandLabel(handshakeTrafficSecret.ToArray(), KeyLabel, ReadOnlySpan<byte>.Empty, resultBuffer);

            return resultBuffer;
        }

        public ReadOnlyMemory<byte> CreateHandshakeIv(ReadOnlyMemory<byte> handshakeTrafficSecret)
        {
            var resultBuffer = new byte[IvSize];

            HkdfExpandLabel(handshakeTrafficSecret.ToArray(), IvLabel, ReadOnlySpan<byte>.Empty, resultBuffer);

            return resultBuffer;
        }

        public ReadOnlyMemory<byte> CreateVerifyData(ReadOnlyMemory<byte> secret, ReadOnlyMemory<byte> finishedHash)
        {
            var labelBuffer = new byte[HashLength];
            var resultBuffer = new byte[HashLength];

            HkdfExpandLabel(secret.ToArray(), FinishedLabel, ReadOnlySpan<byte>.Empty, labelBuffer);
            HkdfExtract(labelBuffer, finishedHash.Span, resultBuffer);

            return resultBuffer;
        }

        private void HkdfExpandLabel(byte[] secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, Span<byte> output)
        {
            Span<byte> labelBuffer = stackalloc byte[LabelMaxSize];

            var labelLength = CreateHkdfLabel(label, context, output.Length, labelBuffer);

            HkdfExpand(secret, labelBuffer.Slice(0, labelLength), output);
        }

        private void HkdfExpand(byte[] prk, ReadOnlySpan<byte> info, Span<byte> output)
        {
            using var algorithm = IncrementalHash.CreateHMAC(algorithmName, prk);

            var currentBlockStart = 0;
            var currentBlockLength = 0;
            var currentRemaining = output.Length;

            for (int i = 1; currentRemaining > 0; i++)
            {
                Span<byte> currentInfoBuffer = stackalloc byte[currentBlockLength + info.Length + 1];
                Span<byte> currentBlockBuffer = stackalloc byte[HashLength];

                output.Slice(currentBlockStart, currentBlockLength).CopyTo(currentInfoBuffer);
                info.CopyTo(currentInfoBuffer.Slice(currentBlockLength));
                currentInfoBuffer[currentInfoBuffer.Length - 1] = (byte)i;
                currentBlockLength = HkdfExtract(algorithm, currentInfoBuffer, currentBlockBuffer);
                currentBlockBuffer.Slice(0, Math.Min(currentBlockLength, currentRemaining)).CopyTo(output.Slice(output.Length - currentRemaining));
                currentRemaining -= currentBlockLength;
                currentBlockStart += currentBlockLength;
            }
        }

        private int HkdfExtract(byte[] key, ReadOnlySpan<byte> data, Span<byte> buffer)
        {
            using var algorithm = IncrementalHash.CreateHMAC(algorithmName, key);

            return HkdfExtract(algorithm, data, buffer);
        }

        private int HkdfExtract(IncrementalHash algorithm, ReadOnlySpan<byte> data, Span<byte> buffer)
        {
            algorithm.AppendData(data);

            if(!algorithm.TryGetHashAndReset(buffer, out var written))
            {
                throw new EncryptionException();
            }

            return written;
        }

        private int CreateHkdfLabel(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int length, Span<byte> buffer)
        {
            var remainings = buffer;

            WriteLength(ref remainings, length);
            WriteLabel(ref remainings, label);
            WriteContext(ref remainings, context);

            return buffer.Length - remainings.Length;
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

        private int HashLength
        {
            get
            {
                if (algorithmName == HashAlgorithmName.SHA1)
                {
                    return 160 / 8;
                }
                else if (algorithmName == HashAlgorithmName.SHA256)
                {
                    return 256 / 8;
                }
                else if (algorithmName == HashAlgorithmName.SHA384)
                {
                    return 384 / 8;
                }
                else if (algorithmName == HashAlgorithmName.SHA512)
                {
                    return 512 / 8;
                }
                else if (algorithmName == HashAlgorithmName.MD5)
                {
                    return 128 / 8;
                }
                else
                {
                    throw new NotSupportedException(nameof(algorithmName));
                }
            }
        }
    }
}
