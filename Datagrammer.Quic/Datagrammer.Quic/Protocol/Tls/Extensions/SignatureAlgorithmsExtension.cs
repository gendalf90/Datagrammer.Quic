using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct SignatureAlgorithmsExtension
    {
        private static SignatureScheme[] supported =
        {
            SignatureScheme.RSA_PKCS1_SHA256,
            SignatureScheme.RSA_PSS_RSAE_SHA256,
            SignatureScheme.ECDSA_SECP256R1_SHA256
        };

        private readonly ReadOnlyMemory<byte> bytes;

        private SignatureAlgorithmsExtension(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out SignatureAlgorithmsExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new SignatureAlgorithmsExtension();
            remainings = bytes;

            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if (type != ExtensionType.SignatureAlgorithms)
            {
                return false;
            }

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 0..ushort.MaxValue, out remainings);

            result = new SignatureAlgorithmsExtension(payload);

            return true;
        }

        public static void WriteFromList(ref Span<byte> destination, params SignatureScheme[] schemes)
        {
            ExtensionType.SignatureAlgorithms.WriteBytes(ref destination);

            var context = ExtensionVectorPayload.StartWriting(ref destination, 0..ushort.MaxValue);

            for(int i = 0; i < schemes.Length; i++)
            {
                schemes[i].WriteBytes(ref destination);
            }

            context.Complete(ref destination);
        }

        public static void WriteSupported(ref Span<byte> destination)
        {
            WriteFromList(ref destination, supported);
        }

        public void WriteBytes(ref Span<byte> destination)
        {
            ExtensionType.SignatureAlgorithms.WriteBytes(ref destination);

            var context = ExtensionVectorPayload.StartWriting(ref destination, 0..ushort.MaxValue);

            if (!bytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(bytes.Length);

            context.Complete(ref destination);
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
