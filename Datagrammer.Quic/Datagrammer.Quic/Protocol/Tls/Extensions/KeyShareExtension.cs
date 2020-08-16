using Datagrammer.Quic.Protocol.Error;
using System;
using System.IO;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct KeyShareExtension
    {
        private static NamedGroup[] supported = new NamedGroup[]
        {
            NamedGroup.X25519
        };

        private readonly ReadOnlyMemory<byte> publicEntryBytes;
        private readonly ReadOnlyMemory<byte> privateEntryBytes;

        private KeyShareExtension(ReadOnlyMemory<byte> publicEntryBytes, ReadOnlyMemory<byte> privateEntryBytes)
        {
            this.publicEntryBytes = publicEntryBytes;
            this.privateEntryBytes = privateEntryBytes;
        }

        public static KeyShareExtension GenerateClientKeys()
        {
            using (var publicStream = new MemoryStream())
            using (var privateStream = new MemoryStream())
            {
                foreach(var group in supported.AsSpan())
                {
                    WriteClientKeys(group, publicStream, privateStream);
                }

                return new KeyShareExtension(publicStream.ToArray(), privateStream.ToArray());
            }
        }

        private static void WriteClientKeys(NamedGroup group, Stream publicStream, Stream privateStream)
        {
            var entries = GenerateEntries(group);

            WriteEntry(publicStream, entries.publicKeyEntry);
            WriteEntry(privateStream, entries.privateKeyEntry);
        }

        private static (KeyShareEntry publicKeyEntry, KeyShareEntry privateKeyEntry) GenerateEntries(NamedGroup group)
        {
            var privateKey = group.GeneratePrivateKey();
            var publicKey = group.GeneratePublicKey(privateKey);

            return (new KeyShareEntry(group, publicKey), new KeyShareEntry(group, privateKey));
        }

        private static void WriteEntry(Stream stream, KeyShareEntry entry)
        {
            entry.Group.WriteBytes(stream);
            ByteVector.WriteVector(stream, 0..ushort.MaxValue, entry.Key);
        }

        public void WriteClientPublicKeys(ref Span<byte> destination)
        {
            ExtensionType.KeyShare.WriteBytes(ref destination);

            var payloadContext = ExtensionPayload.StartWriting(ref destination);
            var context = ByteVector.StartVectorWriting(ref destination, 0..ushort.MaxValue);

            if(!publicEntryBytes.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(0, publicEntryBytes.Length);

            context.Complete(ref destination);
            payloadContext.Complete(ref destination);
        }

        //private static KeyShareEntry[] GenerateEntries()
        //{
        //    var generatedEntries = new KeyShareEntry[Supported.Length];

        //    for (int i = 0; i < generatedEntries.Length; i++)
        //    {
        //        generatedEntries[i] = GenerateEntry(Supported[i]);
        //    }

        //    return generatedEntries;
        //}

        //private static KeyShareEntry GenerateEntry(NamedGroup group)
        //{
        //    var privateKey = group.GeneratePrivateKey();
        //    var publicKey = group.GeneratePublicKey(privateKey);

        //    return new KeyShareEntry(group, publicKey, privateKey);
        //}

        //private static void WriteEntry(ref Span<byte> destination, KeyShareEntry entry)
        //{
        //    entry.NamedGroup.WriteBytes(ref destination);

        //    var context = ByteVector.StartVectorWriting(ref destination, 0..ushort.MaxValue);

        //    if (!entry.PublicKey.Span.TryCopyTo(destination))
        //    {
        //        throw new EncodingException();
        //    }

        //    destination = destination.Slice(entry.PublicKey.Length);

        //    context.Complete(ref destination);
        //}

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out KeyShareExtension result, out ReadOnlyMemory<byte> remainings)
        {
            result = new KeyShareExtension();
            remainings = bytes;
            
            var type = ExtensionType.Parse(bytes, out var afterTypeBytes);

            if (type != ExtensionType.KeyShare)
            {
                return false;
            }

            var payload = ExtensionPayload.Slice(afterTypeBytes, out remainings);

            //result = new KeyShareExtension(payload);

            return true;
        }

        //public bool TryWriteServerKey(ref Span<byte> destination, out KeyShareExtension result)
        //{
        //    var entries = ByteVector.SliceVectorBytes(bytes, 0..ushort.MaxValue, out var remainings);

        //    if(!remainings.IsEmpty)
        //    {
        //        throw new EncodingException();
        //    }

        //    if(!TrySliceFirstSupportedEntry(entries, out var entry))
        //    {
        //        throw new EncryptionException();
        //    }

        //    var generatedServerEntry = GenerateEntry(entry.NamedGroup);

        //    ExtensionType.KeyShare.WriteBytes(ref destination);

        //    var payloadContext = ExtensionPayload.StartWriting(ref destination);

        //    WriteEntry(ref destination, generatedServerEntry);

        //    payloadContext.Complete(ref destination);

        //    result = new KeyShareExtension();
        //}

        //private bool TrySliceFirstSupportedEntry(ReadOnlyMemory<byte> bytes, out KeyShareEntry result)
        //{
        //    result = new KeyShareEntry();

        //    while (!bytes.IsEmpty)
        //    {
        //        if (SliceEntry(ref bytes, out result))
        //        {
        //            return true;
        //        }
        //    }

        //    return false;
        //}

        //private bool SliceEntry(ref ReadOnlyMemory<byte> bytes, out KeyShareEntry result)
        //{
        //    var isGroupSupported = SliceGroup(ref bytes, out var group);
        //    var publicKey = ByteVector.SliceVectorBytes(bytes, 0..ushort.MaxValue, out bytes);

        //    result = new KeyShareEntry(group, publicKey, ReadOnlyMemory<byte>.Empty);

        //    return isGroupSupported;
        //}

        private bool SliceGroup(ref ReadOnlyMemory<byte> bytes, out NamedGroup result)
        {
            result = null;

            foreach(var group in supported.AsSpan())
            {
                if (group.TrySliceBytes(ref bytes))
                {
                    return true;
                }
            }

            NamedGroup.SliceBytes(ref bytes);

            return false;
        }

        public static void WriteClientEntry(ref Span<byte> destination, NamedGroup group, ReadOnlyMemory<byte> publicKey)
        {
            ExtensionType.KeyShare.WriteBytes(ref destination);

            var payloadContext = ExtensionPayload.StartWriting(ref destination);
            var context = ByteVector.StartVectorWriting(ref destination, 0..ushort.MaxValue);

            group.WriteBytes(ref destination);
            WriteKey(ref destination, publicKey);

            context.Complete(ref destination);
            payloadContext.Complete(ref destination);
        }

        private static void WriteKey(ref Span<byte> destination, ReadOnlyMemory<byte> key)
        {
            var context = ByteVector.StartVectorWriting(ref destination, 0..ushort.MaxValue);

            if(!key.Span.TryCopyTo(destination))
            {
                throw new EncodingException();
            }

            destination = destination.Slice(key.Length);

            context.Complete(ref destination);
        }

        public void WriteBytes(ref Span<byte> destination)
        {
            ExtensionType.KeyShare.WriteBytes(ref destination);

            var context = ExtensionPayload.StartWriting(ref destination);

            //if (!bytes.Span.TryCopyTo(destination))
            //{
            //    throw new EncodingException();
            //}

            //destination = destination.Slice(bytes.Length);

            context.Complete(ref destination);
        }

        //public override string ToString()
        //{
        //    return BitConverter.ToString(bytes.ToArray());
        //}

        private readonly struct KeyShareEntry
        {
            public KeyShareEntry(NamedGroup group, ReadOnlyMemory<byte> key)
            {
                Group = group;
                Key = key;
            }

            public NamedGroup Group { get; }

            public ReadOnlyMemory<byte> Key { get; }
        }
    }
}
