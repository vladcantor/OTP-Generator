namespace TOTP_GenerationTests
{
    [TestClass]
    public class OTPGeneratorTests
    {
        [TestMethod]
        public void TestLowEnd_30_SEC()
        {
            var testedTime = new DateTime(2021, 11, 22, 13, 55, 23, 555, DateTimeKind.Utc);
            var userId = "vladc";
            var code = OTPGenerator.GenerateTOTP(userId, testedTime);
            Assert.IsTrue(OTPGenerator.ValidateTOTP(code, userId, testedTime.AddSeconds(5)));
        }

        [TestMethod]
        public void TestHighEnd_30_SEC()
        {
            var testedTime = new DateTime(2021, 11, 22, 13, 55, 45, 555, DateTimeKind.Utc);
            var userId = "vladc";
            var code = OTPGenerator.GenerateTOTP(userId, testedTime);
            Assert.IsTrue(OTPGenerator.ValidateTOTP(code, userId, testedTime.AddSeconds(10)));
        }

        [TestMethod]
        public void TestLowEnd_30_SEC_Expired()
        {
            var testedTime = new DateTime(2021, 11, 22, 13, 55, 23, 555, DateTimeKind.Utc);
            var userId = "vladc";
            var code = OTPGenerator.GenerateTOTP(userId, testedTime);
            Assert.IsFalse(OTPGenerator.ValidateTOTP(code, userId, testedTime.AddSeconds(13)));
        }

        [TestMethod]
        public void TestHighEnd_30_SEC_Expired()
        {
            var testedTime = new DateTime(2021, 11, 22, 13, 55, 45, 555, DateTimeKind.Utc);
            var userId = "vladc";
            var code = OTPGenerator.GenerateTOTP(userId, testedTime);
            Assert.IsFalse(OTPGenerator.ValidateTOTP(code, userId, testedTime.AddSeconds(15)));
        }

        [TestMethod]
        public void Test_Diff_Username()
        {
            var testedTime = new DateTime(2021, 11, 22, 13, 55, 45, 555, DateTimeKind.Utc);
            var userId = "vladc";
            var code = OTPGenerator.GenerateTOTP(userId, testedTime);
            Assert.IsFalse(OTPGenerator.ValidateTOTP(code, "vladcc", testedTime.AddSeconds(5)));
        }

        [TestMethod]
        public void Test_Username_20_bytes_long_Same()
        {
            var testedTime = new DateTime(2021, 11, 22, 13, 55, 45, 555, DateTimeKind.Utc);
            var userId = "4k90yr3l2s0zklnxvrhx";
            var code = OTPGenerator.GenerateTOTP(userId, testedTime);
            Assert.IsTrue(OTPGenerator.ValidateTOTP(code, userId, testedTime.AddSeconds(5)));
        }

        [TestMethod]
        public void Test_Username_20_bytes_long_Dif()
        {
            var testedTime = new DateTime(2021, 11, 22, 13, 55, 45, 555, DateTimeKind.Utc);
            var userId = "4k90yr3l2s0zklnxvrh";
            var code = OTPGenerator.GenerateTOTP(userId+"q", testedTime);
            Assert.IsFalse(OTPGenerator.ValidateTOTP(code, userId+"t", testedTime.AddSeconds(5)));
        }

        [TestMethod]
        public void Test_Username_21_bytes_long_Same()
        {
            var testedTime = new DateTime(2021, 11, 22, 13, 55, 45, 555, DateTimeKind.Utc);
            var userId = "4k90yr3l2s0zklnxvrhxz";
            var code = OTPGenerator.GenerateTOTP(userId , testedTime);
            Assert.IsTrue(OTPGenerator.ValidateTOTP(code, userId, testedTime.AddSeconds(5)));
        }

        [TestMethod]
        public void Test_Username_21_bytes_long_Dif()
        {
            var testedTime = new DateTime(2021, 11, 22, 13, 55, 45, 555, DateTimeKind.Utc);
            var userId = "4k90yr3l2s0zklnxvrhx";
            var code = OTPGenerator.GenerateTOTP(userId+"z", testedTime);
            Assert.IsFalse(OTPGenerator.ValidateTOTP(code, userId+"t", testedTime.AddSeconds(5)));
        }
    }
}