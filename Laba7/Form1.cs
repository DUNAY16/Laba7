using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Laba7
{
    public partial class Form1 : Form
    {
        byte[] randomArray = new byte[0]; 
        bool rbAES, rbRijndeal, rbDES, rbTripleDES, rbRC2;
        Cipher_AES cipher_AES = new Cipher_AES();
        Cipher_DES cipher_DES = new Cipher_DES();
        Cipher_Rijndael cipher_Rijndael = new Cipher_Rijndael();
        Cipher_TripleDES cipher_TripleDES = new Cipher_TripleDES();
        Cipher_RC2 cipher_RC2 = new Cipher_RC2();
        string pathToFileSetting;
        string algorithm;
        bool flagUpdate = false;
        //GISTO gisto = new GISTO();
        byte[] KeyTB, IVTB;
        Form2 form2 = new Form2();
        public Form1()
        {
            InitializeComponent();

            algorithm = "AES";
            comboBox_keyLength_bit.SelectedIndex = 0;
            comboBoxCipher.SelectedIndex = 1;
            comboBoxTypeFilling.SelectedIndex = 3;
            checkBoxIVector.Checked = true;
            radioButtonAES.Checked = true;
            textBoxIVector.Text = "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00";
            randomArray = this.randomArray = KeyGen.generator_Key(int.Parse(comboBox_keyLength_bit.Text) / 8);
            KeyTB = randomArray;
            IVTB = new byte[16];
            textBoxKeyGen.Text = BitConverter.ToString(randomArray);
        }

        private void buttonKeyGen_Click(object sender, EventArgs e)
        {
            
            randomArray = this.randomArray = KeyGen.generator_Key(int.Parse(comboBox_keyLength_bit.Text) / 8);
            KeyTB = randomArray;
            textBoxKeyGen.Text = BitConverter.ToString(randomArray);
        }

        private void button_fileIN_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.InitialDirectory = Directory.GetCurrentDirectory();
                openFileDialog.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*";
                openFileDialog.FilterIndex = 2;
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    //Шлях до файлу
                    string fileINpath = openFileDialog.FileName;
                    textBox_fileIN.Text = fileINpath;
                    FileInfo fileWithKey = new FileInfo(textBox_fileIN.Text);
                    long size1 = fileWithKey.Length;
                    labelFileINLength.Text = ("Розмір: " + size1.ToString() + " байт");
                    labelEntropyFileIN.Text = GISTO.entropy(textBox_fileIN.Text);
                }
            }
        }

        private void button_fileOUT_Click(object sender, EventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();

            saveFileDialog.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*";
            saveFileDialog.FilterIndex = 2;
            saveFileDialog.RestoreDirectory = true;

            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                //Шлях до файлу
                string fileOUTpath = saveFileDialog.FileName;
                textBox_fileOUT.Text = fileOUTpath;
                //if (!File.Exists(textBox_fileOUT.Text))
                //{
                //    File.Create(textBox_fileOUT.Text);
                //}
                //FileInfo fileWithKey = new FileInfo(textBox_fileOUT.Text);
                //long size1 = fileWithKey.Length;
                //labelFileOUTLength.Text = ("Розмір: " + size1.ToString() + " байт");
                //labelEntropyFileOUT.Text = GISTO.entropy(textBox_fileOUT.Text);
            }
        }

        private void buttonCoding_Click(object sender, EventArgs e)
        {
            byte[] arrIn = File.ReadAllBytes(textBox_fileIN.Text);
            //byte[] arrIn = Encoding.UTF8.GetBytes(textBox_fileIN.Text);
            //byte[] arrKey = Encoding.UTF8.GetBytes(textBoxKeyGen.Text);
            //byte[] arrIV = Encoding.UTF8.GetBytes(textBoxIVector.Text);

            byte[] arrEncoding;
            if (rbAES == true)
            {
                Stopwatch stopwatch = new Stopwatch();
                // Begin timing.
                stopwatch.Start();

                if (comboBoxCipher.SelectedIndex == 0)
                {
                    //arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB);
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.Zeros);
                    }
                }
                else if(comboBoxCipher.SelectedIndex == 1)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 2)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 3)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.Zeros);
                    }
                }
                else
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.Zeros);
                    }
                }
                // Stop timing.
                stopwatch.Stop();

                // Write result.
                labelTime.Text = stopwatch.Elapsed.ToString(@"mm\:ss\.fffff");
            }
            else if (rbDES == true)
            {
                Stopwatch stopwatch = new Stopwatch();
                // Begin timing.
                stopwatch.Start();
                //arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB);
                if (comboBoxCipher.SelectedIndex == 0)
                {
                    //arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB);
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 1)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 2)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 3)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.Zeros);
                    }
                }
                else
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_DES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.Zeros);
                    }
                }
                // Stop timing.
                stopwatch.Stop();

                // Write result.
                labelTime.Text = stopwatch.Elapsed.ToString(@"mm\:ss\.fffff");
            }
            else if (rbRijndeal == true)
            {
                Stopwatch stopwatch = new Stopwatch();
                // Begin timing.
                stopwatch.Start();
                //arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB);
                if (comboBoxCipher.SelectedIndex == 0)
                {
                    //arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB);
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 1)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 2)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 3)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.Zeros);
                    }
                }
                else
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_Rijndael.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.Zeros);
                    }
                }
                // Stop timing.
                stopwatch.Stop();

                // Write result.
                labelTime.Text = stopwatch.Elapsed.ToString(@"mm\:ss\.fffff");
            }
            else if (rbTripleDES == true)
            {
                Stopwatch stopwatch = new Stopwatch();
                // Begin timing.
                stopwatch.Start();
                //arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB);
                if (comboBoxCipher.SelectedIndex == 0)
                {
                    //arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB);
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 1)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 2)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 3)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.Zeros);
                    }
                }
                else
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_TripleDES.EncryptStringToBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.Zeros);
                    }
                }
                // Stop timing.
                stopwatch.Stop();

                // Write result.
                labelTime.Text = stopwatch.Elapsed.ToString(@"mm\:ss\.fffff");
            }
            else if (rbRC2 == true)
            {
                Stopwatch stopwatch = new Stopwatch();
                // Begin timing.
                stopwatch.Start();
                //arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB);
                if (comboBoxCipher.SelectedIndex == 0)
                {
                    //arrEncoding = cipher_AES.EncryptStringToBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB);
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 1)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 2)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 3)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.Zeros);
                    }
                }
                else
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.PKCS7);
                    }
                    else
                    {
                        arrEncoding = cipher_RC2.EncryptStringToBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.Zeros);
                    }
                }
                // Stop timing.
                stopwatch.Stop();

                // Write result.
                labelTime.Text = stopwatch.Elapsed.ToString(@"mm\:ss\.fffff");
            }
            else
            {
                arrEncoding = null;
                MessageBox.Show("Оберіть алгоритм шифрування");
            }
            File.WriteAllBytes(textBox_fileOUT.Text, arrEncoding);

            FileInfo fileWithKey = new FileInfo(textBox_fileOUT.Text);
            long size1 = fileWithKey.Length;
            labelFileOUTLength.Text = ("Розмір: " + size1.ToString() + " байт");
            labelEntropyFileOUT.Text = GISTO.entropy(textBox_fileOUT.Text);
        }

        private void buttonDecoding_Click(object sender, EventArgs e)
        {
            byte[] arrIn = File.ReadAllBytes(textBox_fileIN.Text);
            //byte[] arrIn = Encoding.UTF8.GetBytes(textBox_fileIN.Text);
            //byte[] arrKey = Encoding.UTF8.GetBytes(textBoxKeyGen.Text);
            //byte[] arrIV = Encoding.UTF8.GetBytes(textBoxIVector.Text);
            //string str = Encoding.UTF8.GetString(arrIn);

            byte[] resultDec;
            if (rbAES == true)
            {
                Stopwatch stopwatch = new Stopwatch();
                // Begin timing.
                stopwatch.Start();
                if (comboBoxCipher.SelectedIndex == 0)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ANSIX923);
                    }
                    else if(comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 1)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 2)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 3)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.Zeros);
                    }
                }
                else
                {
                    //resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS);
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.Zeros);
                    }
                }
                // Stop timing.
                stopwatch.Stop();

                // Write result.
                labelTime.Text = stopwatch.Elapsed.ToString(@"mm\:ss\.fffff");
            }
            else if (rbDES == true)
            {
                Stopwatch stopwatch = new Stopwatch();
                // Begin timing.
                stopwatch.Start();
                //resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB);
                if (comboBoxCipher.SelectedIndex == 0)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 1)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 2)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 3)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.Zeros);
                    }
                }
                else
                {
                    //resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS);
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_DES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.Zeros);
                    }
                }
                // Stop timing.
                stopwatch.Stop();

                // Write result.
                labelTime.Text = stopwatch.Elapsed.ToString(@"mm\:ss\.fffff");
            }
            else if (rbRijndeal == true)
            {
                Stopwatch stopwatch = new Stopwatch();
                // Begin timing.
                stopwatch.Start();
                //resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB);
                if (comboBoxCipher.SelectedIndex == 0)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 1)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 2)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 3)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.Zeros);
                    }
                }
                else
                {
                    //resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS);
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_Rijndael.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.Zeros);
                    }
                }
                // Stop timing.
                stopwatch.Stop();

                // Write result.
                labelTime.Text = stopwatch.Elapsed.ToString(@"mm\:ss\.fffff");
            }
            else if (rbTripleDES == true)
            {
                Stopwatch stopwatch = new Stopwatch();
                // Begin timing.
                stopwatch.Start();
                //resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB);
                if (comboBoxCipher.SelectedIndex == 0)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 1)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 2)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 3)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.Zeros);
                    }
                }
                else
                {
                    //resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS);
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_TripleDES.DecryptStringFromBytes(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.Zeros);
                    }
                }
                // Stop timing.
                stopwatch.Stop();

                // Write result.
                labelTime.Text = stopwatch.Elapsed.ToString(@"mm\:ss\.fffff");
            }
            else if (rbRC2 == true)
            {
                Stopwatch stopwatch = new Stopwatch();
                // Begin timing.
                stopwatch.Start();
                //resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB);
                if (comboBoxCipher.SelectedIndex == 0)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.ECB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 1)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CBC, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 2)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.OFB, PaddingMode.Zeros);
                    }
                }
                else if (comboBoxCipher.SelectedIndex == 3)
                {
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CFB, PaddingMode.Zeros);
                    }
                }
                else
                {
                    //resultDec = cipher_AES.DecryptStringFromBytes_Aes(arrIn, KeyTB, IVTB, CipherMode.CTS);
                    if (comboBoxTypeFilling.SelectedIndex == 0)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ANSIX923);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 1)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.ISO10126);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 2)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.None);
                    }
                    else if (comboBoxTypeFilling.SelectedIndex == 3)
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.PKCS7);
                    }
                    else
                    {
                        resultDec = cipher_RC2.DecryptStringFromBytes_RC2(arrIn, KeyTB, IVTB, CipherMode.CTS, PaddingMode.Zeros);
                    }
                }
                // Stop timing.
                stopwatch.Stop();

                // Write result.
                labelTime.Text = stopwatch.Elapsed.ToString(@"mm\:ss\.fffff");
            }
            else
            {
                resultDec = null;
                MessageBox.Show("Оберіть алгоритм шифрування");
            }
            //byte[] resultDec = Encoding.UTF8.GetBytes(arrDencoding);
            File.WriteAllBytes(textBox_fileOUT.Text, resultDec);

            FileInfo fileWithKey = new FileInfo(textBox_fileOUT.Text);
            long size1 = fileWithKey.Length;
            labelFileOUTLength.Text = ("Розмір: " + size1.ToString() + " байт");
            labelEntropyFileOUT.Text = GISTO.entropy(textBox_fileOUT.Text);
        }

        private void buttonIVKeyGen_Click(object sender, EventArgs e)
        {
            try
            {
                if (rbAES == true)
                {
                    byte[] arr = this.randomArray = KeyGen.generator_Key(128 / 8);
                    textBoxIVector.Text = BitConverter.ToString(arr);
                    IVTB = arr;
                }
                else if (rbDES == true)
                {
                    byte[] arr = this.randomArray = KeyGen.generator_Key(64 / 8);
                    textBoxIVector.Text = BitConverter.ToString(arr);
                    IVTB = arr;
                }
                else if (rbRijndeal == true)
                {
                    byte[] arr = this.randomArray = KeyGen.generator_Key(128 / 8);
                    textBoxIVector.Text = BitConverter.ToString(arr);
                    IVTB = arr;
                }
                else if (rbTripleDES == true)
                {
                    byte[] arr = this.randomArray = KeyGen.generator_Key(64 / 8);
                    textBoxIVector.Text = BitConverter.ToString(arr);
                    IVTB = arr;
                }
                else if (rbRC2 == true)
                {
                    byte[] arr = this.randomArray = KeyGen.generator_Key(64 / 8);
                    textBoxIVector.Text = BitConverter.ToString(arr);
                    IVTB = arr;
                }
            }
            catch(Exception ex)
            {
                MessageBox.Show(ex.Message, "Ошибка!", MessageBoxButtons.OK, MessageBoxIcon.Error); 
            }
        }

        private void checkBoxIVector_CheckedChanged(object sender, EventArgs e)
        {
            if (!checkBoxIVector.Checked)
            {
                try
                {
                    if (rbAES == true)
                    {
                        byte[] arr = this.randomArray = KeyGen.generator_Key(128 / 8);
                        textBoxIVector.Text = BitConverter.ToString(arr);
                        IVTB = arr;
                        textBoxIVector.ReadOnly = false;
                        buttonIVKeyGen.Enabled = true;
                        toolTip1.SetToolTip(buttonIVKeyGen, "Генерувати новий Вектор ініціалізації");
                    }
                    else if (rbDES == true)
                    {
                        byte[] arr = this.randomArray = KeyGen.generator_Key(64 / 8);
                        textBoxIVector.Text = BitConverter.ToString(arr);
                        IVTB = arr;
                        textBoxIVector.ReadOnly = false;
                        buttonIVKeyGen.Enabled = true;
                        toolTip1.SetToolTip(buttonIVKeyGen, "Генерувати новий Вектор ініціалізації");
                    }
                    else if (rbRijndeal == true)
                    {
                        byte[] arr = this.randomArray = KeyGen.generator_Key(128 / 8);
                        textBoxIVector.Text = BitConverter.ToString(arr);
                        IVTB = arr;
                        textBoxIVector.ReadOnly = false;
                        buttonIVKeyGen.Enabled = true;
                        toolTip1.SetToolTip(buttonIVKeyGen, "Генерувати новий Вектор ініціалізації");
                    }
                    else if (rbTripleDES == true)
                    {
                        byte[] arr = this.randomArray = KeyGen.generator_Key(64 / 8);
                        textBoxIVector.Text = BitConverter.ToString(arr);
                        IVTB = arr;
                        textBoxIVector.ReadOnly = false;
                        buttonIVKeyGen.Enabled = true;
                        toolTip1.SetToolTip(buttonIVKeyGen, "Генерувати новий Вектор ініціалізації");
                    }
                    else if (rbRC2 == true)
                    {
                        byte[] arr = this.randomArray = KeyGen.generator_Key(64 / 8);
                        textBoxIVector.Text = BitConverter.ToString(arr);
                        IVTB = arr;
                        textBoxIVector.ReadOnly = false;
                        buttonIVKeyGen.Enabled = true;
                        toolTip1.SetToolTip(buttonIVKeyGen, "Генерувати новий Вектор ініціалізації");
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Ошибка!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else
            {
                try
                {
                    if (rbAES == true)
                    {
                        textBoxIVector.ReadOnly = true;
                        buttonIVKeyGen.Enabled = false;
                        textBoxIVector.Text = "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00";
                        IVTB = new byte[16];
                    }
                    else if (rbDES == true)
                    {
                        textBoxIVector.ReadOnly = true;
                        buttonIVKeyGen.Enabled = false;
                        textBoxIVector.Text = "00-00-00-00-00-00-00-00";
                        IVTB = new byte[8];
                    }
                    else if (rbRijndeal == true)
                    {
                        textBoxIVector.ReadOnly = true;
                        buttonIVKeyGen.Enabled = false;
                        textBoxIVector.Text = "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00";
                        IVTB = new byte[16];
                    }
                    else if (rbTripleDES == true)
                    {
                        textBoxIVector.ReadOnly = true;
                        buttonIVKeyGen.Enabled = false;
                        textBoxIVector.Text = "00-00-00-00-00-00-00-00";
                        IVTB = new byte[8];
                    }
                    else if (rbRC2 == true)
                    {
                        textBoxIVector.ReadOnly = true;
                        buttonIVKeyGen.Enabled = false;
                        textBoxIVector.Text = "00-00-00-00-00-00-00-00";
                        IVTB = new byte[8];
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Ошибка!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                
            }
        }

        private void comboBox_keyLength_bit_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (flagUpdate == false)
            {
                randomArray = this.randomArray = KeyGen.generator_Key(int.Parse(comboBox_keyLength_bit.Text) / 8);
                KeyTB = randomArray;
                textBoxKeyGen.Text = BitConverter.ToString(randomArray);
            }
        }

        private void button_fileKeyOUT_Click(object sender, EventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();

            saveFileDialog.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*";
            saveFileDialog.FilterIndex = 2;
            saveFileDialog.RestoreDirectory = true;

            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                //Шлях до файлу
                string fileOUTpath = saveFileDialog.FileName;
                pathToFileSetting = fileOUTpath;

                string[] settings = new string[4];
                settings[0] = textBoxKeyGen.Text;
                settings[1] = textBoxIVector.Text;
                settings[2] = comboBox_keyLength_bit.Text;
                settings[3] = algorithm;

                //File.WriteAllBytes(fileOUTpath, Encoding.UTF8.GetBytes(textBoxKeyGen.Text));
                File.WriteAllLines(fileOUTpath, settings);

                //textBox_fileOUT.Text = fileOUTpath;
            }
        }

        private void button_fileKeyUpdate_Click(object sender, EventArgs e)
        {
            flagUpdate = true;
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.InitialDirectory = Directory.GetCurrentDirectory();
                openFileDialog.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*";
                openFileDialog.FilterIndex = 2;
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    //Шлях до файлу
                    string fileINpath = openFileDialog.FileName;
                    //textBox_fileIN.Text = fileINpath;

                    string[] settings = new string[4];
                    settings = File.ReadAllLines(fileINpath);

                    if (settings[3] == "AES")
                    {
                        rbAES = true;
                        comboBox_keyLength_bit.Enabled = true;
                        radioButtonAES.Checked = true;
                        if (settings[2] == "128")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.Items.Add("192");
                            comboBox_keyLength_bit.Items.Add("256");
                            comboBox_keyLength_bit.SelectedIndex = 0;
                        }
                        if (settings[2] == "192")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.Items.Add("192");
                            comboBox_keyLength_bit.Items.Add("256");
                            comboBox_keyLength_bit.SelectedIndex = 1;
                        }
                        if (settings[2] == "256")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.Items.Add("192");
                            comboBox_keyLength_bit.Items.Add("256");
                            comboBox_keyLength_bit.SelectedIndex = 2;
                        }
                    }
                    if (settings[3] == "DES")
                    {
                        rbDES = true;
                        radioButtonDES.Checked = true;
                        comboBox_keyLength_bit.SelectedIndex = 0;
                        comboBox_keyLength_bit.Enabled = false;
                    }
                    if (settings[3] == "Rijndeal")
                    {
                        rbRijndeal = true;
                        comboBox_keyLength_bit.Enabled = true;
                        radioButtonRijndeal.Checked = true;
                        if (settings[2] == "128")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.Items.Add("192");
                            comboBox_keyLength_bit.Items.Add("256");
                            comboBox_keyLength_bit.SelectedIndex = 0;
                        }
                        if (settings[2] == "192")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.Items.Add("192");
                            comboBox_keyLength_bit.Items.Add("256");
                            comboBox_keyLength_bit.SelectedIndex = 1;
                        }
                        if (settings[2] == "256")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.Items.Add("192");
                            comboBox_keyLength_bit.Items.Add("256");
                            comboBox_keyLength_bit.SelectedIndex = 2;
                        }
                    }
                    if (settings[3] == "TripleDES")
                    {
                        rbTripleDES = true;
                        comboBox_keyLength_bit.Enabled = true;
                        radioButtonTripleDES.Checked = true;
                        if (settings[2] == "128")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.Items.Add("192");
                            comboBox_keyLength_bit.SelectedIndex = 0;
                        }
                        if (settings[2] == "192")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.Items.Add("192");
                            comboBox_keyLength_bit.SelectedIndex = 1;
                        }
                    }
                    if (settings[3] == "RC2")
                    {
                        rbRC2 = true;
                        comboBox_keyLength_bit.Enabled = true;
                        radioButtonRC2.Checked = true;
                        if (settings[2] == "40")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 0;
                        }
                        if (settings[2] == "48")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 1;
                        }
                        if (settings[2] == "56")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 2;
                        }
                        if (settings[2] == "64")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 3;
                        }
                        if (settings[2] == "72")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 4;
                        }
                        if (settings[2] == "80")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 5;
                        }
                        if (settings[2] == "88")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 6;
                        }
                        if (settings[2] == "96")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 7;
                        }
                        if (settings[2] == "104")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 8;
                        }
                        if (settings[2] == "112")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 9;
                        }
                        if (settings[2] == "120")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 10;
                        }
                        if (settings[2] == "128")
                        {
                            comboBox_keyLength_bit.Items.Clear();
                            comboBox_keyLength_bit.Items.Add("40");
                            comboBox_keyLength_bit.Items.Add("48");
                            comboBox_keyLength_bit.Items.Add("56");
                            comboBox_keyLength_bit.Items.Add("64");
                            comboBox_keyLength_bit.Items.Add("72");
                            comboBox_keyLength_bit.Items.Add("80");
                            comboBox_keyLength_bit.Items.Add("88");
                            comboBox_keyLength_bit.Items.Add("96");
                            comboBox_keyLength_bit.Items.Add("104");
                            comboBox_keyLength_bit.Items.Add("112");
                            comboBox_keyLength_bit.Items.Add("120");
                            comboBox_keyLength_bit.Items.Add("128");
                            comboBox_keyLength_bit.SelectedIndex = 11;
                        }
                    }
                    textBoxKeyGen.Text = settings[0];
                    textBoxIVector.Text = settings[1];
                    comboBox_keyLength_bit.Text = settings[2];
                    algorithm = settings[3];
                    //textBoxKeyGen.Text = File.ReadAllText(fileINpath);
                }
            }
            flagUpdate = false;
        }

        private void проПрограмуToolStripMenuItem_Click(object sender, EventArgs e)
        {
            form2.Show();
        }

        private void вихідToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Close();
        }


        private void radioButtonAES_CheckedChanged(object sender, EventArgs e)
        {
            if (flagUpdate == false)
            {
                algorithm = "AES";
                randomArray = this.randomArray = KeyGen.generator_Key(128 / 8);
                KeyTB = randomArray;
                textBoxKeyGen.Text = BitConverter.ToString(randomArray);
                if (!checkBoxIVector.Checked)
                {
                    byte[] arr = this.randomArray = KeyGen.generator_Key(128 / 8);
                    textBoxIVector.Text = BitConverter.ToString(arr);
                    IVTB = arr;
                }
                else
                {
                    textBoxIVector.Text = "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00";
                    IVTB = new byte[16];
                }

                comboBox_keyLength_bit.Enabled = true;
                comboBox_keyLength_bit.Items.Clear();
                comboBox_keyLength_bit.Items.Add("128");
                comboBox_keyLength_bit.Items.Add("192");
                comboBox_keyLength_bit.Items.Add("256");
                comboBox_keyLength_bit.SelectedIndex = 0;
                rbAES = true;
                rbRijndeal = false;
                rbDES = false;
                rbTripleDES = false;
                rbRC2 = false;
            }
        }

        private void radioButtonRijndeal_CheckedChanged(object sender, EventArgs e)
        {
            algorithm = "Rijndeal";
            if (flagUpdate == false)
            {
                randomArray = this.randomArray = KeyGen.generator_Key(128 / 8);
                KeyTB = randomArray;
                textBoxKeyGen.Text = BitConverter.ToString(randomArray);
                if (!checkBoxIVector.Checked)
                {
                    byte[] arr = this.randomArray = KeyGen.generator_Key(128 / 8);
                    textBoxIVector.Text = BitConverter.ToString(arr);
                    IVTB = arr;
                }
                else
                {
                    textBoxIVector.Text = "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00";
                    IVTB = new byte[16];
                }

                comboBox_keyLength_bit.Enabled = true;
                comboBox_keyLength_bit.Items.Clear();
                comboBox_keyLength_bit.Items.Add("128");
                comboBox_keyLength_bit.Items.Add("192");
                comboBox_keyLength_bit.Items.Add("256");
                comboBox_keyLength_bit.SelectedIndex = 0;
                rbAES = false;
                rbRijndeal = true;
                rbDES = false;
                rbTripleDES = false;
                rbRC2 = false;
            }
        }

        private void radioButtonDES_CheckedChanged(object sender, EventArgs e)
        {
            if (flagUpdate == false)
            {
                algorithm = "DES";
                randomArray = this.randomArray = KeyGen.generator_Key(64 / 8);
                KeyTB = randomArray;
                textBoxKeyGen.Text = BitConverter.ToString(randomArray);
                if (!checkBoxIVector.Checked)
                {
                    byte[] arr = this.randomArray = KeyGen.generator_Key(64 / 8);
                    textBoxIVector.Text = BitConverter.ToString(arr);
                    IVTB = arr;
                }
                else
                {
                    textBoxIVector.Text = "00-00-00-00-00-00-00-00";
                    IVTB = new byte[8];
                }

                comboBox_keyLength_bit.Text = "64";
                comboBox_keyLength_bit.Enabled = false;
                rbAES = false;
                rbRijndeal = false;
                rbDES = true;
                rbTripleDES = false;
                rbRC2 = false;
            }
        }

        private void radioButtonTripleDES_CheckedChanged(object sender, EventArgs e)
        {
            algorithm = "TripleDES";
            if (flagUpdate == false)
            {
                randomArray = this.randomArray = KeyGen.generator_Key(128 / 8);
                KeyTB = randomArray;
                textBoxKeyGen.Text = BitConverter.ToString(randomArray);
                if (!checkBoxIVector.Checked)
                {
                    byte[] arr = this.randomArray = KeyGen.generator_Key(64 / 8);
                    textBoxIVector.Text = BitConverter.ToString(arr);
                    IVTB = arr;
                }
                else
                {
                    textBoxIVector.Text = "00-00-00-00-00-00-00-00";
                    IVTB = new byte[8];
                }

                comboBox_keyLength_bit.Items.Clear();
                comboBox_keyLength_bit.Items.Add("128");
                comboBox_keyLength_bit.Items.Add("192");

                comboBox_keyLength_bit.Enabled = true;
                comboBox_keyLength_bit.SelectedIndex = 0;
                rbAES = false;
                rbRijndeal = false;
                rbDES = false;
                rbTripleDES = true;
                rbRC2 = false;
            }
        }

        private void radioButtonRC2_CheckedChanged(object sender, EventArgs e)
        {

            if (flagUpdate == false)
            {
                randomArray = this.randomArray = KeyGen.generator_Key(int.Parse(comboBox_keyLength_bit.Text) / 8);
                KeyTB = randomArray;
                textBoxKeyGen.Text = BitConverter.ToString(randomArray);
                if (!checkBoxIVector.Checked)
                {
                    byte[] arr = this.randomArray = KeyGen.generator_Key(64 / 8);
                    textBoxIVector.Text = BitConverter.ToString(arr);
                    IVTB = arr;
                }
                else
                {
                    textBoxIVector.Text = "00-00-00-00-00-00-00-00";
                    IVTB = new byte[8];
                }
                algorithm = "RC2";
                comboBox_keyLength_bit.Enabled = true;
                comboBox_keyLength_bit.Items.Clear();
                comboBox_keyLength_bit.Items.Add("40");
                comboBox_keyLength_bit.Items.Add("48");
                comboBox_keyLength_bit.Items.Add("56");
                comboBox_keyLength_bit.Items.Add("64");
                comboBox_keyLength_bit.Items.Add("72");
                comboBox_keyLength_bit.Items.Add("80");
                comboBox_keyLength_bit.Items.Add("88");
                comboBox_keyLength_bit.Items.Add("96");
                comboBox_keyLength_bit.Items.Add("104");
                comboBox_keyLength_bit.Items.Add("112");
                comboBox_keyLength_bit.Items.Add("120");
                comboBox_keyLength_bit.Items.Add("128");
                comboBox_keyLength_bit.SelectedIndex = 0;

                comboBox_keyLength_bit.Enabled = true;
                comboBox_keyLength_bit.SelectedIndex = 0;
                rbAES = false;
                rbRijndeal = false;
                rbDES = false;
                rbTripleDES = false;
                rbRC2 = true;
            }
        }
    }
}
