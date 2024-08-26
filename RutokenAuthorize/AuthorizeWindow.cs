using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;
using System.Collections;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;

namespace RutokenAuthorize
{
    public partial class AuthorizeWindow : Form
    {
        public AuthorizeWindow()
        {
            InitializeComponent();
        }

        private void find_all_keypairs()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Establishing a connection with Rutoken in the first available slot
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Opening RW session
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Performing user authentication
                    session.Login(CKU.CKU_USER, password_textbox.Text);

                    // Template for searching for an RSA keypair
                    var publicKeyAttributes = new List<ObjectAttribute>
                    {
                        new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                        new ObjectAttribute(CKA.CKA_TOKEN, true),
                    };

                    List<ObjectHandle> publicKeys = session.FindAllObjects(publicKeyAttributes);

                    log("FOUND " + publicKeys.Count() + " KEY PAIRS\n");

                    for (int i = 0; i < publicKeys.Count; i++)
                    {
                        var publicKeyHandle = publicKeys[i];
                        byte[] modulus = session.GetAttributeValue(publicKeyHandle, new List<CKA>
                        {
                            CKA.CKA_MODULUS
                        })[0].GetValueAsByteArray();
                        string modulus_string = BitConverter.ToString(modulus).Replace("-", "");

                        byte[] exponent = session.GetAttributeValue(publicKeyHandle, new List<CKA>
                        {
                            CKA.CKA_PUBLIC_EXPONENT
                        })[0].GetValueAsByteArray();
                        string exponent_string = BitConverter.ToString(exponent).Replace("-", "");

                        byte[] id = session.GetAttributeValue(publicKeyHandle, new List<CKA>
                        {
                            CKA.CKA_ID
                        })[0].GetValueAsByteArray();
                        string id_string = Encoding.ASCII.GetString(id);

                        log("KEY PAIR " + i + ":");
                        log("\tID: " + id_string);
                        log("\tMODULUS: " + modulus_string);
                        log("\tPUBLIC_EXPONENT: " + exponent_string);
                        log("");
                    }
                    session.Logout();
                }
            }
        }

        private void find_and_verify(string modulus_string, string exponent_string)
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Establishing a connection with Rutoken in the first available slot
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Opening RW session
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Performing user authentication
                    session.Login(CKU.CKU_USER, password_textbox.Text);

                    // Template for searching for an RSA private key
                    var privateKeyAttributes = new List<ObjectAttribute>
                    {
                        new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                        new ObjectAttribute(CKA.CKA_TOKEN, true),
                        new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, HexStringToByteArray(exponent_string)),
                        new ObjectAttribute(CKA.CKA_MODULUS, HexStringToByteArray(modulus_string)),
                    };
                    List<ObjectHandle> privateKeys = session.FindAllObjects(privateKeyAttributes);

                    // Template for searching for the corresponding public key
                    var publicKeyAttributes = new List<ObjectAttribute>
                    {
                        new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                        new ObjectAttribute(CKA.CKA_TOKEN, true),
                        new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT,  HexStringToByteArray(exponent_string)),
                        new ObjectAttribute(CKA.CKA_MODULUS, HexStringToByteArray(modulus_string)),
                    };
                    List<ObjectHandle> publicKeys = session.FindAllObjects(publicKeyAttributes);

                    if (privateKeys.Count > 0 && publicKeys.Count > 0)
                    {
                        byte[] id = session.GetAttributeValue(publicKeys[0], new List<CKA>
                        {
                            CKA.CKA_ID
                        })[0].GetValueAsByteArray();
                        string id_string = Encoding.ASCII.GetString(id);

                        log("VERIFYING KEYPAIR ID:" + id_string);


                        var publicKeyHandle = publicKeys[0];
                        byte[] modulus = session.GetAttributeValue(publicKeyHandle, new List<CKA>
                        {
                            CKA.CKA_MODULUS
                        })[0].GetValueAsByteArray();

                        byte[] exponent = session.GetAttributeValue(publicKeyHandle, new List<CKA>
                        {
                            CKA.CKA_PUBLIC_EXPONENT
                        })[0].GetValueAsByteArray();

                        RsaKeyParameters publicKey = new RsaKeyParameters(false, new Org.BouncyCastle.Math.BigInteger(1, modulus), new Org.BouncyCastle.Math.BigInteger(1, exponent));


                        // Generating random data
                        byte[] dataToEncrypt = new byte[32];
                        using (var rng = new RNGCryptoServiceProvider())
                        {
                            rng.GetBytes(dataToEncrypt);
                        }
                        log("SOURCE DATA: " + BitConverter.ToString(dataToEncrypt));

                        try
                        {
                            // Encrypting data using the public key
                            var encryptionMechanism = new Mechanism(CKM.CKM_RSA_PKCS);

                            byte[] encryptedData = EncryptDataWithRSA(dataToEncrypt, publicKey);
                            log("ENCRYPTED DATA: " + BitConverter.ToString(encryptedData));

                            // Decrypting data using the private key
                            var decryptionMechanism = new Mechanism(CKM.CKM_RSA_PKCS);
                            byte[] decryptedData = session.Decrypt(decryptionMechanism, privateKeys[0], encryptedData);

                            log("DECRYPTED DATA: " + BitConverter.ToString(decryptedData));

                            // Validating the authenticity of the data
                            bool isValid = StructuralComparisons.StructuralEqualityComparer.Equals(dataToEncrypt, decryptedData);
                            log("VALIDATION RESULT: " + isValid);
                        }
                        catch (Exception e) { log("VALIDATION FAILED"); }
                    }
                    else
                    {
                        log("NO KEY PAIR FOUND");
                    }

                    session.Logout();
                }
            }
        }

        static byte[] EncryptDataWithRSA(byte[] data, RsaKeyParameters publicKey)
        {
            // Using RSA with PKCS1Padding for encryption
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());
            engine.Init(true, publicKey);

            return engine.ProcessBlock(data, 0, data.Length);
        }

        public void create_key_pair(string id)
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RW session
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, password_textbox.Text);

                    // Generating keys for RSA encryption
                    ObjectHandle privateKeyHandle = null;
                    ObjectHandle publicKeyHandle = null;
                    Helpers.GenerateRSAKeyPair(session, out publicKeyHandle, out privateKeyHandle, id);

                    session.Logout();
                }
            }
        }
        private void find_keys_button_Click(object sender, EventArgs e)
        {
            find_all_keypairs();
        }
        private void log(string msg)
        {
            logTextBox.AppendText(msg + '\n');
        }

        private void maskedTextBox1_MaskInputRejected(object sender, MaskInputRejectedEventArgs e)
        {

        }

        private void create_keys_button_Click(object sender, EventArgs e)
        {
            create_key_pair(ID_textbox.Text);
        }

        private void verify_button_Click(object sender, EventArgs e)
        {
            find_and_verify(modulus_textbox.Text, exponent_textbox.Text);
        }
        static byte[] HexStringToByteArray(string hex)
        {
            // The string length must be even, as each byte is represented by two characters
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Invalid length of the hex string.");

            byte[] byteArray = new byte[hex.Length / 2];

            for (int i = 0; i < hex.Length; i += 2)
            {
                // Parsing each two characters as a hexadecimal number
                byteArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return byteArray;
        }

    }
}
