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
        private static readonly byte[] ClientApplicationTrafficLabel = Encoding.ASCII.GetBytes("tls13 c ap traffic");
        private static readonly byte[] ServerApplicationTrafficLabel = Encoding.ASCII.GetBytes("tls13 s ap traffic");
        private static readonly byte[] KeyLabel = Encoding.ASCII.GetBytes("tls13 key");
        private static readonly byte[] IvLabel = Encoding.ASCII.GetBytes("tls13 iv");
        private static readonly byte[] InitialSalt = { 175, 191, 236, 40, 153, 147, 210, 76, 158, 151, 134, 241, 156, 97, 17, 224, 67, 144, 168, 153 };
        private static readonly byte[] ClientInitialLabel = Encoding.ASCII.GetBytes("tls13 client in");
        private static readonly byte[] ServerInitialLabel = Encoding.ASCII.GetBytes("tls13 server in");
        private static readonly byte[] QuicKeyLabel = Encoding.ASCII.GetBytes("tls13 quic key");
        private static readonly byte[] QuicIvLabel = Encoding.ASCII.GetBytes("tls13 quic iv");
        private static readonly byte[] QuicHeaderProtectionLabel = Encoding.ASCII.GetBytes("tls13 quic hp");

        private readonly HashAlgorithmName algorithmName;

        private readonly byte[] earlySecret;
        private readonly byte[] emptyHash;
        private readonly byte[] zeroBuffer;

        private Hash(HashAlgorithmName algorithmName)
        {
            this.algorithmName = algorithmName;

            earlySecret = ComputeEarlySecret();
            emptyHash = ComputeEmptyHash();
            zeroBuffer = new byte[HashLength];
        }

        private byte[] ComputeEarlySecret()
        {
            var buffer = new byte[HashLength];

            HkdfExtract(buffer, buffer, buffer);

            return buffer;
        }

        private byte[] ComputeEmptyHash()
        {
            return CreateHash(ReadOnlySpan<byte>.Empty).ToArray();
        }

        public static Hash Sha256 { get; } = new Hash(HashAlgorithmName.SHA256);

        public ValueBuffer CreateHash(ReadOnlySpan<byte> bytes)
        {
            using var algorithm = IncrementalHash.CreateHash(algorithmName);

            Span<byte> buffer = stackalloc byte[HashLength];

            HkdfExtract(algorithm, bytes, buffer);

            return buffer;
        }

        public ValueBuffer CreateHandshakeSecret(ValueBuffer sharedSecret)
        {
            Span<byte> resultBuffer = stackalloc byte[HashLength];
            Span<byte> sharedSecretBuffer = stackalloc byte[sharedSecret.Length];

            sharedSecret.CopyTo(sharedSecretBuffer);

            HkdfExpandLabel(earlySecret, DerivedLabel, emptyHash, resultBuffer);
            HkdfExtract(resultBuffer, sharedSecretBuffer, resultBuffer);

            return resultBuffer;
        }

        public ValueBuffer CreateClientHandshakeTrafficSecret(ValueBuffer handshakeSecret, ValueBuffer helloHash)
        {
            Span<byte> resultBuffer = stackalloc byte[HashLength];
            Span<byte> secretBuffer = stackalloc byte[handshakeSecret.Length];
            Span<byte> hashBuffer = stackalloc byte[helloHash.Length];

            handshakeSecret.CopyTo(secretBuffer);
            helloHash.CopyTo(hashBuffer);

            HkdfExpandLabel(secretBuffer, ClientHandshakeTrafficLabel, hashBuffer, resultBuffer);

            return resultBuffer;
        }

        public ValueBuffer CreateServerHandshakeTrafficSecret(ValueBuffer handshakeSecret, ValueBuffer helloHash)
        {
            Span<byte> resultBuffer = stackalloc byte[HashLength];
            Span<byte> secretBuffer = stackalloc byte[handshakeSecret.Length];
            Span<byte> hashBuffer = stackalloc byte[helloHash.Length];

            handshakeSecret.CopyTo(secretBuffer);
            helloHash.CopyTo(hashBuffer);

            HkdfExpandLabel(secretBuffer, ServerHandshakeTrafficLabel, hashBuffer, resultBuffer);

            return resultBuffer;
        }

        public ValueBuffer CreateKey(ValueBuffer trafficSecret)
        {
            Span<byte> resultBuffer = stackalloc byte[KeySize];
            Span<byte> secretBuffer = stackalloc byte[trafficSecret.Length];

            trafficSecret.CopyTo(secretBuffer);

            HkdfExpandLabel(secretBuffer, KeyLabel, ReadOnlySpan<byte>.Empty, resultBuffer);

            return resultBuffer;
        }

        public ValueBuffer CreateIv(ValueBuffer trafficSecret)
        {
            Span<byte> resultBuffer = stackalloc byte[IvSize];
            Span<byte> secretBuffer = stackalloc byte[trafficSecret.Length];

            trafficSecret.CopyTo(secretBuffer);

            HkdfExpandLabel(secretBuffer, IvLabel, ReadOnlySpan<byte>.Empty, resultBuffer);

            return resultBuffer;
        }

        public ValueBuffer CreateVerifyData(ValueBuffer secret, ValueBuffer finishedHash)
        {
            Span<byte> resultBuffer = stackalloc byte[HashLength];
            Span<byte> secretBuffer = stackalloc byte[secret.Length];
            Span<byte> hashBuffer = stackalloc byte[finishedHash.Length];

            secret.CopyTo(secretBuffer);
            finishedHash.CopyTo(hashBuffer);

            HkdfExpandLabel(secretBuffer, FinishedLabel, ReadOnlySpan<byte>.Empty, resultBuffer);
            HkdfExtract(resultBuffer, hashBuffer, resultBuffer);

            return resultBuffer;
        }

        public ValueBuffer CreateMasterSecret(ValueBuffer handshakeSecret)
        {
            Span<byte> resultBuffer = stackalloc byte[HashLength];
            Span<byte> secretBuffer = stackalloc byte[handshakeSecret.Length];

            handshakeSecret.CopyTo(secretBuffer);

            HkdfExpandLabel(secretBuffer, DerivedLabel, emptyHash, resultBuffer);
            HkdfExtract(resultBuffer, zeroBuffer, resultBuffer);

            return resultBuffer;
        }

        public ValueBuffer CreateClientApplicationTrafficSecret(ValueBuffer masterSecret, ValueBuffer handshakeHash)
        {
            Span<byte> resultBuffer = stackalloc byte[HashLength];
            Span<byte> secretBuffer = stackalloc byte[masterSecret.Length];
            Span<byte> hashBuffer = stackalloc byte[handshakeHash.Length];

            masterSecret.CopyTo(secretBuffer);
            handshakeHash.CopyTo(hashBuffer);

            HkdfExpandLabel(secretBuffer, ClientApplicationTrafficLabel, hashBuffer, resultBuffer);

            return resultBuffer;
        }

        public ValueBuffer CreateServerApplicationTrafficSecret(ValueBuffer masterSecret, ValueBuffer handshakeHash)
        {
            Span<byte> resultBuffer = stackalloc byte[HashLength];
            Span<byte> secretBuffer = stackalloc byte[masterSecret.Length];
            Span<byte> hashBuffer = stackalloc byte[handshakeHash.Length];

            masterSecret.CopyTo(secretBuffer);
            handshakeHash.CopyTo(hashBuffer);

            HkdfExpandLabel(secretBuffer, ServerApplicationTrafficLabel, hashBuffer, resultBuffer);

            return resultBuffer;
        }

        public (ValueBuffer MasterSecret, ValueBuffer TrafficSecret, ValueBuffer Key, ValueBuffer Iv) CreateClientApplicationSecrets(
            ValueBuffer handshakeSecret, 
            ValueBuffer handshakeHash)
        {
            return CreateApplicationSecrets(handshakeSecret, handshakeHash, ClientApplicationTrafficLabel);
        }

        public (ValueBuffer MasterSecret, ValueBuffer TrafficSecret, ValueBuffer Key, ValueBuffer Iv) CreateServerApplicationSecrets(
            ValueBuffer handshakeSecret,
            ValueBuffer handshakeHash)
        {
            return CreateApplicationSecrets(handshakeSecret, handshakeHash, ServerApplicationTrafficLabel);
        }

        private (ValueBuffer MasterSecret, ValueBuffer TrafficSecret, ValueBuffer Key, ValueBuffer Iv) CreateApplicationSecrets(
            ValueBuffer handshakeSecret, 
            ValueBuffer handshakeHash, 
            ReadOnlySpan<byte> trafficLabel)
        {
            Span<byte> masterSecretBuffer = stackalloc byte[HashLength];
            Span<byte> handshakeSecretBuffer = stackalloc byte[handshakeSecret.Length];
            Span<byte> trafficSecretBuffer = stackalloc byte[HashLength];
            Span<byte> handshakeHashBuffer = stackalloc byte[handshakeHash.Length];
            Span<byte> keyBuffer = stackalloc byte[KeySize];
            Span<byte> ivBuffer = stackalloc byte[IvSize];

            handshakeSecret.CopyTo(handshakeSecretBuffer);
            handshakeHash.CopyTo(handshakeHashBuffer);

            HkdfExpandLabel(handshakeSecretBuffer, DerivedLabel, emptyHash, masterSecretBuffer); // master secret
            HkdfExtract(masterSecretBuffer, zeroBuffer, masterSecretBuffer); // master secret
            HkdfExpandLabel(masterSecretBuffer, trafficLabel, handshakeHashBuffer, trafficSecretBuffer); // traffic secret
            HkdfExpandLabel(trafficSecretBuffer, KeyLabel, ReadOnlySpan<byte>.Empty, keyBuffer); // key
            HkdfExpandLabel(trafficSecretBuffer, IvLabel, ReadOnlySpan<byte>.Empty, ivBuffer); // iv

            return (new ValueBuffer(masterSecretBuffer), new ValueBuffer(trafficSecretBuffer), new ValueBuffer(keyBuffer), new ValueBuffer(ivBuffer));
        }

        public (ValueBuffer Key, ValueBuffer Iv, ValueBuffer Hp) CreateClientInitialSecrets(ReadOnlySpan<byte> cid)
        {
            return CreateInitialSecrets(cid, ClientInitialLabel);
        }

        public (ValueBuffer Key, ValueBuffer Iv, ValueBuffer Hp) CreateServerInitialSecrets(ReadOnlySpan<byte> cid)
        {
            return CreateInitialSecrets(cid, ServerInitialLabel);
        }

        private (ValueBuffer Key, ValueBuffer Iv, ValueBuffer Hp) CreateInitialSecrets(ReadOnlySpan<byte> cid, ReadOnlySpan<byte> initialLabel)
        {
            Span<byte> keyBuffer = stackalloc byte[KeySize];
            Span<byte> hpBuffer = stackalloc byte[KeySize];
            Span<byte> ivBuffer = stackalloc byte[IvSize];
            Span<byte> initialSecretBuffer = stackalloc byte[HashLength];

            HkdfExtract(InitialSalt, cid, initialSecretBuffer); // common_initial_secret
            HkdfExpandLabel(initialSecretBuffer, initialLabel, ReadOnlySpan<byte>.Empty, initialSecretBuffer); // initial_secret
            HkdfExpandLabel(initialSecretBuffer, QuicKeyLabel, ReadOnlySpan<byte>.Empty, keyBuffer); // key
            HkdfExpandLabel(initialSecretBuffer, QuicIvLabel, ReadOnlySpan<byte>.Empty, ivBuffer); // iv
            HkdfExpandLabel(initialSecretBuffer, QuicHeaderProtectionLabel, ReadOnlySpan<byte>.Empty, hpBuffer); // hp

            return (new ValueBuffer(keyBuffer), new ValueBuffer(ivBuffer), new ValueBuffer(hpBuffer));
        }

        private void HkdfExpandLabel(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, Span<byte> output)
        {
            Span<byte> labelBuffer = stackalloc byte[LabelMaxSize];

            var labelLength = CreateHkdfLabel(label, context, output.Length, labelBuffer);

            HkdfExpand(secret, labelBuffer.Slice(0, labelLength), output);
        }

        private void HkdfExpand(ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, Span<byte> output)
        {
            using var algorithm = IncrementalHash.CreateHMAC(algorithmName, prk);

            Span<byte> buffer = stackalloc byte[HashLength + info.Length + 1];

            var currentInfo = buffer.Slice(HashLength, info.Length + 1);
            var hkdf = buffer.Slice(0, HashLength);

            ref byte index = ref buffer[info.Length + HashLength];

            info.CopyTo(currentInfo);

            for (index = 1; !output.IsEmpty; index++)
            {
                HkdfExtract(algorithm, currentInfo, hkdf);

                var lengthToOutput = Math.Min(hkdf.Length, output.Length);

                hkdf.Slice(0, lengthToOutput).CopyTo(output);

                output = output.Slice(lengthToOutput);

                currentInfo = buffer;
            }
        }

        private void HkdfExtract(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> buffer)
        {
            using var algorithm = IncrementalHash.CreateHMAC(algorithmName, key);

            HkdfExtract(algorithm, data, buffer);
        }

        private void HkdfExtract(IncrementalHash algorithm, ReadOnlySpan<byte> data, Span<byte> buffer)
        {
            algorithm.AppendData(data);

            if(!algorithm.TryGetHashAndReset(buffer, out _))
            {
                throw new EncryptionException();
            }
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
            NetworkBitConverter.WriteUnaligned(bytes, (ulong)length, 2);

            bytes = bytes.Slice(2);
        }

        private void WriteLabel(ref Span<byte> bytes, ReadOnlySpan<byte> label)
        {
            var vectorContext = ByteVector.StartVectorWriting(ref bytes, 0..255);

            label.CopyTo(bytes);

            bytes = bytes.Slice(label.Length);

            vectorContext.Complete(ref bytes);
        }

        private void WriteContext(ref Span<byte> bytes, ReadOnlySpan<byte> context)
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
