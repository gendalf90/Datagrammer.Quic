using Datagrammer.Quic.Protocol.Error;
using System;
using System.Collections.Generic;
using System.IO;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct KeyShareExtension
    {
        private readonly ReadOnlyMemory<byte> bytes;
        private readonly bool isList;

        private KeyShareExtension(ReadOnlyMemory<byte> bytes, bool isList)
        {
            this.bytes = bytes;
            this.isList = isList;
        }

        public static KeyShareExtension CreateFromEntries(IEnumerable<KeyShareEntry> entries)
        {
            using (var stream = new MemoryStream())
            {
                foreach (var entry in entries)
                {
                    entry.Write(stream);
                }

                return new KeyShareExtension(stream.ToArray(), true);
            }
        }

        public static KeyShareExtension CreateFromEntry(KeyShareEntry entry)
        {
            using (var stream = new MemoryStream())
            {
                entry.Write(stream);

                return new KeyShareExtension(stream.ToArray(), false);
            }
        }

        public static KeyShareExtension CreatePrivateKeys(ReadOnlySpan<NamedGroup> groups)
        {
            using (var stream = new MemoryStream())
            {
                foreach(var group in groups)
                {
                    GeneratePrivateKey(stream, group);
                }

                return new KeyShareExtension(stream.ToArray(), true);
            }
        }

        private static void GeneratePrivateKey(Stream stream, NamedGroup group)
        {
            var privateKeyEntry = KeyShareEntry.GeneratePrivateKey(group);

            privateKeyEntry.Write(stream);
        }

        public KeyShareExtension CreatePublicKeys()
        {
            using (var stream = new MemoryStream())
            {
                var remainings = bytes;

                while(!remainings.IsEmpty)
                {
                    CreatePublicKeyEntryFromPrivate(stream, remainings, out remainings);
                }

                return new KeyShareExtension(stream.ToArray(), true);
            }
        }

        private void CreatePublicKeyEntryFromPrivate(Stream stream, ReadOnlyMemory<byte> privateKeyEntryData, out ReadOnlyMemory<byte> remainings)
        {
            var privateKeyEntry = KeyShareEntry.Parse(privateKeyEntryData, out remainings);
            var publicKeyEntry = privateKeyEntry.GeneratePublicKey();

            publicKeyEntry.Write(stream);
        }

        public void Write(ref Span<byte> destination)
        {
            ExtensionType.KeyShare.WriteBytes(ref destination);

            var context = ExtensionPayload.StartWriting(ref destination);

            if(isList)
            {
                WriteVectorBytes(ref destination);
            }
            else
            {
                WriteBytes(ref destination);
            }

            context.Complete(ref destination);
        }

        private void WriteVectorBytes(ref Span<byte> destination)
        {
            var context = ByteVector.StartVectorWriting(ref destination, 0..ushort.MaxValue);

            WriteBytes(ref destination);

            context.Complete(ref destination);
        }

        private void WriteBytes(ref Span<byte> destination)
        {
            if (!bytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(bytes.Length);
        }

        public static bool TryParseList(ReadOnlyMemory<byte> bytes, out KeyShareExtension result, out ReadOnlyMemory<byte> remainings)
        {
            remainings = bytes;
            result = new KeyShareExtension();

            if (ExtensionType.Parse(bytes, out var afterTypeBytes) != ExtensionType.KeyShare)
            {
                return false;
            }

            var payload = ExtensionVectorPayload.Slice(afterTypeBytes, 0..ushort.MaxValue, out remainings);

            result = new KeyShareExtension(payload, true);

            return true;
        }

        public static bool TryParseOne(ReadOnlyMemory<byte> bytes, out KeyShareExtension result, out ReadOnlyMemory<byte> remainings)
        {
            remainings = bytes;
            result = new KeyShareExtension();

            if (ExtensionType.Parse(bytes, out var afterTypeBytes) != ExtensionType.KeyShare)
            {
                return false;
            }

            var payload = ExtensionPayload.Slice(afterTypeBytes, out remainings);

            result = new KeyShareExtension(payload, false);

            return true;
        }

        public override string ToString()
        {
            return BitConverter.ToString(bytes.ToArray());
        }
    }
}
