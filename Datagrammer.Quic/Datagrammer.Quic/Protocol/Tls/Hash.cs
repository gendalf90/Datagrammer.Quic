using System;
using System.Security.Cryptography;
using System.Text;

namespace Datagrammer.Quic.Protocol.Tls
{
    public class Hash
    {
        private const int LabelMaxSize = 528;

        private static readonly byte[] FinishedLable = Encoding.ASCII.GetBytes("tls13 finished");

        private readonly HashAlgorithm algorithm;
        private readonly HashAlgorithmName name;

        private Hash(HashAlgorithmName name, HashAlgorithm algorithm)
        {
            this.name = name;
            this.algorithm = algorithm;
        }

        private static Hash Sha256 { get; } = new Hash(HashAlgorithmName.SHA256, SHA256.Create());

        //private ReadOnlySpan<byte> ComputeFinishedKey(ReadOnlySpan<byte> secret)
        //{
            
        //}

        private ReadOnlySpan<byte> CreateHkdfLabel(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context)
        {
            var buffer = new Span<byte>(new byte[LabelMaxSize]);
            var remainings = buffer;

            WriteLength(ref remainings);
            WriteLabel(ref remainings, label);
            WriteContext(ref remainings, context);

            return buffer.Slice(0, buffer.Length - remainings.Length);
        }

        private void WriteLength(ref Span<byte> bytes)
        {
            var length = algorithm.HashSize / 8;
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
