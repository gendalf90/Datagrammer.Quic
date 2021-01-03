using Datagrammer.Quic.Protocol.Packet;
using System;
using Xunit;

namespace Tests.Packet
{
    public class VariableLengthIntegerTests
    {
        [Theory]
        [InlineData("ffffffffffffffff", 4611686018427387903, 8)]
        [InlineData("c2197c5eff14e88c", 151288809941952652, 8)]
        [InlineData("9d7f3e7d", 494878333, 4)]
        [InlineData("7bbd", 15293, 2)]
        [InlineData("40ff", 255, 2)]
        [InlineData("25", 37, 1)]
        [InlineData("00", 0, 1)]
        public void ReadValue_ResultIsExpected(string bytes, ulong expectedValue, int expectedLength)
        {
            //Arrange
            //Act
            var resultValue = VariableLengthEncoding.Decode(Utils.ParseHexString(bytes), out var resultLength);

            //Assert
            Assert.Equal(expectedValue, resultValue);
            Assert.Equal(expectedLength, resultLength);
        }

        [Theory]
        [InlineData("ffffffffffffffff", 4611686018427387903, 8)]
        [InlineData("c2197c5eff14e88c", 151288809941952652, 8)]
        [InlineData("9d7f3e7d", 494878333, 4)]
        [InlineData("7bbd", 15293, 2)]
        [InlineData("40ff", 255, 2)]
        [InlineData("25", 37, 1)]
        [InlineData("00", 0, 1)]
        public void WriteValue_ResultIsExpected(string expectedBytes, ulong value, int expectedLength)
        {
            //Arrange
            var buffer = new byte[8];

            //Act
            VariableLengthEncoding.Encode(buffer, value, out var resultLength);
            Array.Resize(ref buffer, resultLength);

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(buffer), true);
            Assert.Equal(expectedLength, resultLength);
        }
    }
}
