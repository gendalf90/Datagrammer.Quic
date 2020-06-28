using System;
using System.Security.Cryptography;
using System.Text;

namespace Datagrammer.Quic.Protocol.Tls
{
    public class Hash
    {
        private const int LabelMaxSize = 528;
        private const string HmacPrefix = "HMAC";

        private static readonly byte[] FinishedLabel = Encoding.ASCII.GetBytes("tls13 finished");

        private readonly KeyedHashAlgorithm algorithm;
        private readonly HashAlgorithmName algorithmName;
        private readonly string hmacAlgorithmName;

        private Hash(HashAlgorithmName algorithmName)
        {
            this.algorithmName = algorithmName;

            hmacAlgorithmName = HmacPrefix + algorithmName.Name;
            algorithm = KeyedHashAlgorithm.Create(hmacAlgorithmName);
        }

        public static Hash Sha256 { get; } = new Hash(HashAlgorithmName.SHA256);

        public ReadOnlyMemory<byte> CreateVerifyData(ReadOnlyMemory<byte> secret, ReadOnlyMemory<byte> finishedHash)
        {
            var finishedKey = ComputeKey(secret.ToArray(), FinishedLabel);

            return KeyedHash(finishedKey, finishedHash.ToArray());
        }

        private byte[] ComputeKey(byte[] secret, byte[] label)
        {
            var length = algorithm.HashSize / 8;
            var hkdfLabel = CreateHkdfLabel(label, Array.Empty<byte>(), length);

            return HkdfExpand(secret, hkdfLabel, length);
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
                resultBlock = KeyedHash(prk, currentInfo);
                Array.Copy(resultBlock, 0, result, outputLength - bytesRemaining, Math.Min(resultBlock.Length, bytesRemaining));
                bytesRemaining -= resultBlock.Length;
            }

            return result;
        }

        private byte[] KeyedHash(byte[] key, byte[] data)
        {
            using (var currentAlgorithm = KeyedHashAlgorithm.Create(hmacAlgorithmName))
            {
                currentAlgorithm.Key = key;

                return currentAlgorithm.ComputeHash(data);
            }
        }

        private byte[] CreateHkdfLabel(byte[] label, byte[] context, int length)
        {
            Span<byte> buffer = stackalloc byte[LabelMaxSize];

            var remainings = buffer;

            WriteLength(ref remainings, length);
            WriteLabel(ref remainings, label);
            WriteContext(ref remainings, context);

            return buffer.Slice(0, buffer.Length - remainings.Length).ToArray();
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
