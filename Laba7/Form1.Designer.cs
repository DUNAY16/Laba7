
namespace Laba7
{
    partial class Form1
    {
        /// <summary>
        /// Обязательная переменная конструктора.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Освободить все используемые ресурсы.
        /// </summary>
        /// <param name="disposing">истинно, если управляемый ресурс должен быть удален; иначе ложно.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Код, автоматически созданный конструктором форм Windows

        /// <summary>
        /// Требуемый метод для поддержки конструктора — не изменяйте 
        /// содержимое этого метода с помощью редактора кода.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.groupBox5 = new System.Windows.Forms.GroupBox();
            this.labelFileOUTLength = new System.Windows.Forms.Label();
            this.labelEntropyFileOUT = new System.Windows.Forms.Label();
            this.button_fileOUT = new System.Windows.Forms.Button();
            this.textBox_fileOUT = new System.Windows.Forms.TextBox();
            this.groupBox4 = new System.Windows.Forms.GroupBox();
            this.labelFileINLength = new System.Windows.Forms.Label();
            this.labelEntropyFileIN = new System.Windows.Forms.Label();
            this.button_fileIN = new System.Windows.Forms.Button();
            this.textBox_fileIN = new System.Windows.Forms.TextBox();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.groupBox7 = new System.Windows.Forms.GroupBox();
            this.panel2 = new System.Windows.Forms.Panel();
            this.radioButtonRC2 = new System.Windows.Forms.RadioButton();
            this.radioButtonTripleDES = new System.Windows.Forms.RadioButton();
            this.radioButtonDES = new System.Windows.Forms.RadioButton();
            this.radioButtonRijndeal = new System.Windows.Forms.RadioButton();
            this.radioButtonAES = new System.Windows.Forms.RadioButton();
            this.groupBox6 = new System.Windows.Forms.GroupBox();
            this.checkBoxIVector = new System.Windows.Forms.CheckBox();
            this.buttonIVKeyGen = new System.Windows.Forms.Button();
            this.textBoxIVector = new System.Windows.Forms.TextBox();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.buttonKeyGen = new System.Windows.Forms.Button();
            this.textBoxKeyGen = new System.Windows.Forms.TextBox();
            this.panel1 = new System.Windows.Forms.Panel();
            this.button_fileKeyOUT = new System.Windows.Forms.Button();
            this.comboBoxTypeFilling = new System.Windows.Forms.ComboBox();
            this.label3 = new System.Windows.Forms.Label();
            this.button_fileKeyUpdate = new System.Windows.Forms.Button();
            this.comboBoxCipher = new System.Windows.Forms.ComboBox();
            this.label2 = new System.Windows.Forms.Label();
            this.comboBox_keyLength_bit = new System.Windows.Forms.ComboBox();
            this.label1 = new System.Windows.Forms.Label();
            this.groupBox8 = new System.Windows.Forms.GroupBox();
            this.labelTime = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.buttonStop = new System.Windows.Forms.Button();
            this.buttonDecoding = new System.Windows.Forms.Button();
            this.buttonCoding = new System.Windows.Forms.Button();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.довідкаToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.проПрограмуToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.вихідToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolTip1 = new System.Windows.Forms.ToolTip(this.components);
            this.groupBox3.SuspendLayout();
            this.groupBox5.SuspendLayout();
            this.groupBox4.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.groupBox7.SuspendLayout();
            this.panel2.SuspendLayout();
            this.groupBox6.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.panel1.SuspendLayout();
            this.groupBox8.SuspendLayout();
            this.menuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBox3
            // 
            this.groupBox3.Controls.Add(this.groupBox5);
            this.groupBox3.Controls.Add(this.groupBox4);
            this.groupBox3.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.groupBox3.Location = new System.Drawing.Point(13, 32);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Size = new System.Drawing.Size(706, 197);
            this.groupBox3.TabIndex = 3;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "Файл";
            // 
            // groupBox5
            // 
            this.groupBox5.Controls.Add(this.labelFileOUTLength);
            this.groupBox5.Controls.Add(this.labelEntropyFileOUT);
            this.groupBox5.Controls.Add(this.button_fileOUT);
            this.groupBox5.Controls.Add(this.textBox_fileOUT);
            this.groupBox5.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.groupBox5.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.groupBox5.Location = new System.Drawing.Point(3, 109);
            this.groupBox5.Margin = new System.Windows.Forms.Padding(4);
            this.groupBox5.Name = "groupBox5";
            this.groupBox5.Padding = new System.Windows.Forms.Padding(4);
            this.groupBox5.Size = new System.Drawing.Size(700, 85);
            this.groupBox5.TabIndex = 2;
            this.groupBox5.TabStop = false;
            this.groupBox5.Text = "Вихідний";
            // 
            // labelFileOUTLength
            // 
            this.labelFileOUTLength.AutoSize = true;
            this.labelFileOUTLength.Location = new System.Drawing.Point(342, 57);
            this.labelFileOUTLength.Name = "labelFileOUTLength";
            this.labelFileOUTLength.Size = new System.Drawing.Size(111, 22);
            this.labelFileOUTLength.TabIndex = 3;
            this.labelFileOUTLength.Text = "Розмір:  ???";
            // 
            // labelEntropyFileOUT
            // 
            this.labelEntropyFileOUT.AutoSize = true;
            this.labelEntropyFileOUT.Location = new System.Drawing.Point(19, 57);
            this.labelEntropyFileOUT.Name = "labelEntropyFileOUT";
            this.labelEntropyFileOUT.Size = new System.Drawing.Size(131, 22);
            this.labelEntropyFileOUT.TabIndex = 2;
            this.labelEntropyFileOUT.Text = "Ентропія:  ???";
            // 
            // button_fileOUT
            // 
            this.button_fileOUT.Location = new System.Drawing.Point(652, 27);
            this.button_fileOUT.Name = "button_fileOUT";
            this.button_fileOUT.Size = new System.Drawing.Size(41, 26);
            this.button_fileOUT.TabIndex = 1;
            this.button_fileOUT.Text = "...";
            this.button_fileOUT.UseVisualStyleBackColor = true;
            this.button_fileOUT.Click += new System.EventHandler(this.button_fileOUT_Click);
            // 
            // textBox_fileOUT
            // 
            this.textBox_fileOUT.Location = new System.Drawing.Point(8, 27);
            this.textBox_fileOUT.Margin = new System.Windows.Forms.Padding(4);
            this.textBox_fileOUT.Name = "textBox_fileOUT";
            this.textBox_fileOUT.Size = new System.Drawing.Size(637, 30);
            this.textBox_fileOUT.TabIndex = 0;
            // 
            // groupBox4
            // 
            this.groupBox4.Controls.Add(this.labelFileINLength);
            this.groupBox4.Controls.Add(this.labelEntropyFileIN);
            this.groupBox4.Controls.Add(this.button_fileIN);
            this.groupBox4.Controls.Add(this.textBox_fileIN);
            this.groupBox4.Dock = System.Windows.Forms.DockStyle.Top;
            this.groupBox4.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.groupBox4.Location = new System.Drawing.Point(3, 26);
            this.groupBox4.Margin = new System.Windows.Forms.Padding(4);
            this.groupBox4.Name = "groupBox4";
            this.groupBox4.Padding = new System.Windows.Forms.Padding(4);
            this.groupBox4.Size = new System.Drawing.Size(700, 85);
            this.groupBox4.TabIndex = 1;
            this.groupBox4.TabStop = false;
            this.groupBox4.Text = "Вхідний";
            // 
            // labelFileINLength
            // 
            this.labelFileINLength.AutoSize = true;
            this.labelFileINLength.Location = new System.Drawing.Point(342, 57);
            this.labelFileINLength.Name = "labelFileINLength";
            this.labelFileINLength.Size = new System.Drawing.Size(111, 22);
            this.labelFileINLength.TabIndex = 3;
            this.labelFileINLength.Text = "Розмір:  ???";
            // 
            // labelEntropyFileIN
            // 
            this.labelEntropyFileIN.AutoSize = true;
            this.labelEntropyFileIN.Location = new System.Drawing.Point(19, 57);
            this.labelEntropyFileIN.Name = "labelEntropyFileIN";
            this.labelEntropyFileIN.Size = new System.Drawing.Size(131, 22);
            this.labelEntropyFileIN.TabIndex = 2;
            this.labelEntropyFileIN.Text = "Ентропія:  ???";
            // 
            // button_fileIN
            // 
            this.button_fileIN.Location = new System.Drawing.Point(652, 31);
            this.button_fileIN.Name = "button_fileIN";
            this.button_fileIN.Size = new System.Drawing.Size(41, 26);
            this.button_fileIN.TabIndex = 1;
            this.button_fileIN.Text = "...";
            this.button_fileIN.UseVisualStyleBackColor = true;
            this.button_fileIN.Click += new System.EventHandler(this.button_fileIN_Click);
            // 
            // textBox_fileIN
            // 
            this.textBox_fileIN.Location = new System.Drawing.Point(8, 27);
            this.textBox_fileIN.Margin = new System.Windows.Forms.Padding(4);
            this.textBox_fileIN.Name = "textBox_fileIN";
            this.textBox_fileIN.Size = new System.Drawing.Size(637, 30);
            this.textBox_fileIN.TabIndex = 0;
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.groupBox7);
            this.groupBox1.Controls.Add(this.groupBox6);
            this.groupBox1.Controls.Add(this.groupBox2);
            this.groupBox1.Controls.Add(this.panel1);
            this.groupBox1.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.groupBox1.Location = new System.Drawing.Point(16, 236);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(709, 309);
            this.groupBox1.TabIndex = 4;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Параметри";
            // 
            // groupBox7
            // 
            this.groupBox7.Controls.Add(this.panel2);
            this.groupBox7.Location = new System.Drawing.Point(8, 240);
            this.groupBox7.Name = "groupBox7";
            this.groupBox7.Size = new System.Drawing.Size(695, 63);
            this.groupBox7.TabIndex = 10;
            this.groupBox7.TabStop = false;
            this.groupBox7.Text = "Алгоритм шифрування";
            // 
            // panel2
            // 
            this.panel2.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(255)))), ((int)(((byte)(128)))));
            this.panel2.Controls.Add(this.radioButtonRC2);
            this.panel2.Controls.Add(this.radioButtonTripleDES);
            this.panel2.Controls.Add(this.radioButtonDES);
            this.panel2.Controls.Add(this.radioButtonRijndeal);
            this.panel2.Controls.Add(this.radioButtonAES);
            this.panel2.Dock = System.Windows.Forms.DockStyle.Fill;
            this.panel2.Location = new System.Drawing.Point(3, 26);
            this.panel2.Name = "panel2";
            this.panel2.Size = new System.Drawing.Size(689, 34);
            this.panel2.TabIndex = 0;
            // 
            // radioButtonRC2
            // 
            this.radioButtonRC2.AutoSize = true;
            this.radioButtonRC2.Location = new System.Drawing.Point(326, 5);
            this.radioButtonRC2.Name = "radioButtonRC2";
            this.radioButtonRC2.Size = new System.Drawing.Size(67, 26);
            this.radioButtonRC2.TabIndex = 4;
            this.radioButtonRC2.TabStop = true;
            this.radioButtonRC2.Text = "RC2";
            this.radioButtonRC2.UseVisualStyleBackColor = true;
            this.radioButtonRC2.CheckedChanged += new System.EventHandler(this.radioButtonRC2_CheckedChanged);
            // 
            // radioButtonTripleDES
            // 
            this.radioButtonTripleDES.AutoSize = true;
            this.radioButtonTripleDES.Location = new System.Drawing.Point(226, 5);
            this.radioButtonTripleDES.Name = "radioButtonTripleDES";
            this.radioButtonTripleDES.Size = new System.Drawing.Size(117, 26);
            this.radioButtonTripleDES.TabIndex = 3;
            this.radioButtonTripleDES.TabStop = true;
            this.radioButtonTripleDES.Text = "TripleDES";
            this.radioButtonTripleDES.UseVisualStyleBackColor = true;
            this.radioButtonTripleDES.CheckedChanged += new System.EventHandler(this.radioButtonTripleDES_CheckedChanged);
            // 
            // radioButtonDES
            // 
            this.radioButtonDES.AutoSize = true;
            this.radioButtonDES.Location = new System.Drawing.Point(156, 5);
            this.radioButtonDES.Name = "radioButtonDES";
            this.radioButtonDES.Size = new System.Drawing.Size(68, 26);
            this.radioButtonDES.TabIndex = 2;
            this.radioButtonDES.TabStop = true;
            this.radioButtonDES.Text = "DES";
            this.radioButtonDES.UseVisualStyleBackColor = true;
            this.radioButtonDES.CheckedChanged += new System.EventHandler(this.radioButtonDES_CheckedChanged);
            // 
            // radioButtonRijndeal
            // 
            this.radioButtonRijndeal.AutoSize = true;
            this.radioButtonRijndeal.Location = new System.Drawing.Point(70, 5);
            this.radioButtonRijndeal.Name = "radioButtonRijndeal";
            this.radioButtonRijndeal.Size = new System.Drawing.Size(99, 26);
            this.radioButtonRijndeal.TabIndex = 1;
            this.radioButtonRijndeal.TabStop = true;
            this.radioButtonRijndeal.Text = "Rijndeal";
            this.radioButtonRijndeal.UseVisualStyleBackColor = true;
            this.radioButtonRijndeal.CheckedChanged += new System.EventHandler(this.radioButtonRijndeal_CheckedChanged);
            // 
            // radioButtonAES
            // 
            this.radioButtonAES.AutoSize = true;
            this.radioButtonAES.Location = new System.Drawing.Point(8, 5);
            this.radioButtonAES.Name = "radioButtonAES";
            this.radioButtonAES.Size = new System.Drawing.Size(68, 26);
            this.radioButtonAES.TabIndex = 0;
            this.radioButtonAES.TabStop = true;
            this.radioButtonAES.Text = "AES";
            this.radioButtonAES.UseVisualStyleBackColor = true;
            this.radioButtonAES.CheckedChanged += new System.EventHandler(this.radioButtonAES_CheckedChanged);
            // 
            // groupBox6
            // 
            this.groupBox6.Controls.Add(this.checkBoxIVector);
            this.groupBox6.Controls.Add(this.buttonIVKeyGen);
            this.groupBox6.Controls.Add(this.textBoxIVector);
            this.groupBox6.Location = new System.Drawing.Point(8, 163);
            this.groupBox6.Name = "groupBox6";
            this.groupBox6.Size = new System.Drawing.Size(692, 69);
            this.groupBox6.TabIndex = 9;
            this.groupBox6.TabStop = false;
            this.groupBox6.Text = "Вектор ініціалізації";
            // 
            // checkBoxIVector
            // 
            this.checkBoxIVector.AutoSize = true;
            this.checkBoxIVector.Location = new System.Drawing.Point(469, 23);
            this.checkBoxIVector.Name = "checkBoxIVector";
            this.checkBoxIVector.Size = new System.Drawing.Size(82, 26);
            this.checkBoxIVector.TabIndex = 2;
            this.checkBoxIVector.Text = "BI = 0";
            this.checkBoxIVector.UseVisualStyleBackColor = true;
            this.checkBoxIVector.CheckedChanged += new System.EventHandler(this.checkBoxIVector_CheckedChanged);
            // 
            // buttonIVKeyGen
            // 
            this.buttonIVKeyGen.Enabled = false;
            this.buttonIVKeyGen.Image = global::Laba7.Properties.Resources.hand_notebook48;
            this.buttonIVKeyGen.Location = new System.Drawing.Point(391, 13);
            this.buttonIVKeyGen.Name = "buttonIVKeyGen";
            this.buttonIVKeyGen.Size = new System.Drawing.Size(63, 50);
            this.buttonIVKeyGen.TabIndex = 1;
            this.buttonIVKeyGen.UseVisualStyleBackColor = true;
            this.buttonIVKeyGen.Click += new System.EventHandler(this.buttonIVKeyGen_Click);
            // 
            // textBoxIVector
            // 
            this.textBoxIVector.Location = new System.Drawing.Point(7, 26);
            this.textBoxIVector.Name = "textBoxIVector";
            this.textBoxIVector.ReadOnly = true;
            this.textBoxIVector.Size = new System.Drawing.Size(378, 30);
            this.textBoxIVector.TabIndex = 0;
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.buttonKeyGen);
            this.groupBox2.Controls.Add(this.textBoxKeyGen);
            this.groupBox2.Location = new System.Drawing.Point(7, 88);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(693, 69);
            this.groupBox2.TabIndex = 8;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Ключ";
            // 
            // buttonKeyGen
            // 
            this.buttonKeyGen.Image = global::Laba7.Properties.Resources.key2;
            this.buttonKeyGen.Location = new System.Drawing.Point(638, 27);
            this.buttonKeyGen.Name = "buttonKeyGen";
            this.buttonKeyGen.Size = new System.Drawing.Size(49, 26);
            this.buttonKeyGen.TabIndex = 1;
            this.toolTip1.SetToolTip(this.buttonKeyGen, "Генерувати новий ключ шифрування");
            this.buttonKeyGen.UseVisualStyleBackColor = true;
            this.buttonKeyGen.Click += new System.EventHandler(this.buttonKeyGen_Click);
            // 
            // textBoxKeyGen
            // 
            this.textBoxKeyGen.Location = new System.Drawing.Point(7, 26);
            this.textBoxKeyGen.Name = "textBoxKeyGen";
            this.textBoxKeyGen.Size = new System.Drawing.Size(617, 30);
            this.textBoxKeyGen.TabIndex = 0;
            // 
            // panel1
            // 
            this.panel1.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(255)))), ((int)(((byte)(255)))), ((int)(((byte)(128)))));
            this.panel1.Controls.Add(this.button_fileKeyOUT);
            this.panel1.Controls.Add(this.comboBoxTypeFilling);
            this.panel1.Controls.Add(this.label3);
            this.panel1.Controls.Add(this.button_fileKeyUpdate);
            this.panel1.Controls.Add(this.comboBoxCipher);
            this.panel1.Controls.Add(this.label2);
            this.panel1.Controls.Add(this.comboBox_keyLength_bit);
            this.panel1.Controls.Add(this.label1);
            this.panel1.Dock = System.Windows.Forms.DockStyle.Top;
            this.panel1.Location = new System.Drawing.Point(3, 26);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(703, 60);
            this.panel1.TabIndex = 0;
            // 
            // button_fileKeyOUT
            // 
            this.button_fileKeyOUT.Image = global::Laba7.Properties.Resources.open_file48;
            this.button_fileKeyOUT.Location = new System.Drawing.Point(552, 3);
            this.button_fileKeyOUT.Name = "button_fileKeyOUT";
            this.button_fileKeyOUT.Size = new System.Drawing.Size(65, 49);
            this.button_fileKeyOUT.TabIndex = 6;
            this.toolTip1.SetToolTip(this.button_fileKeyOUT, "Зберегти поточні параметри");
            this.button_fileKeyOUT.UseVisualStyleBackColor = true;
            this.button_fileKeyOUT.Click += new System.EventHandler(this.button_fileKeyOUT_Click);
            // 
            // comboBoxTypeFilling
            // 
            this.comboBoxTypeFilling.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxTypeFilling.Font = new System.Drawing.Font("Times New Roman", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.comboBoxTypeFilling.FormattingEnabled = true;
            this.comboBoxTypeFilling.Items.AddRange(new object[] {
            "ANSIX923",
            "ISO10126",
            "None",
            "PKCS7",
            "Zeros"});
            this.comboBoxTypeFilling.Location = new System.Drawing.Point(375, 32);
            this.comboBoxTypeFilling.Name = "comboBoxTypeFilling";
            this.comboBoxTypeFilling.Size = new System.Drawing.Size(84, 27);
            this.comboBoxTypeFilling.TabIndex = 5;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Times New Roman", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.label3.Location = new System.Drawing.Point(218, 35);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(122, 19);
            this.label3.TabIndex = 4;
            this.label3.Text = "Тип заповнення:";
            // 
            // button_fileKeyUpdate
            // 
            this.button_fileKeyUpdate.Image = global::Laba7.Properties.Resources.save48;
            this.button_fileKeyUpdate.Location = new System.Drawing.Point(631, 3);
            this.button_fileKeyUpdate.Name = "button_fileKeyUpdate";
            this.button_fileKeyUpdate.Size = new System.Drawing.Size(66, 49);
            this.button_fileKeyUpdate.TabIndex = 7;
            this.toolTip1.SetToolTip(this.button_fileKeyUpdate, "Відновити збережені параметри");
            this.button_fileKeyUpdate.UseVisualStyleBackColor = true;
            this.button_fileKeyUpdate.Click += new System.EventHandler(this.button_fileKeyUpdate_Click);
            // 
            // comboBoxCipher
            // 
            this.comboBoxCipher.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxCipher.Font = new System.Drawing.Font("Times New Roman", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.comboBoxCipher.FormattingEnabled = true;
            this.comboBoxCipher.Items.AddRange(new object[] {
            "ECB - The Electronic Codebook",
            "CBC - Cipher Block Chianing",
            "OFB - The Output Feedback",
            "CFB - The Cipher Feedback",
            "CTS - The Cipher Text Stealing"});
            this.comboBoxCipher.Location = new System.Drawing.Point(343, 4);
            this.comboBoxCipher.Name = "comboBoxCipher";
            this.comboBoxCipher.Size = new System.Drawing.Size(203, 27);
            this.comboBoxCipher.TabIndex = 3;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Times New Roman", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.label2.Location = new System.Drawing.Point(208, 7);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(153, 19);
            this.label2.TabIndex = 2;
            this.label2.Text = "Режим шифрування:";
            // 
            // comboBox_keyLength_bit
            // 
            this.comboBox_keyLength_bit.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBox_keyLength_bit.FormattingEnabled = true;
            this.comboBox_keyLength_bit.Items.AddRange(new object[] {
            "128",
            "192",
            "256"});
            this.comboBox_keyLength_bit.Location = new System.Drawing.Point(143, 20);
            this.comboBox_keyLength_bit.Name = "comboBox_keyLength_bit";
            this.comboBox_keyLength_bit.Size = new System.Drawing.Size(59, 30);
            this.comboBox_keyLength_bit.TabIndex = 1;
            this.comboBox_keyLength_bit.SelectedIndexChanged += new System.EventHandler(this.comboBox_keyLength_bit_SelectedIndexChanged);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Times New Roman", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.label1.Location = new System.Drawing.Point(5, 25);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(162, 19);
            this.label1.TabIndex = 0;
            this.label1.Text = "Довжина ключа (біт):";
            // 
            // groupBox8
            // 
            this.groupBox8.Controls.Add(this.labelTime);
            this.groupBox8.Controls.Add(this.label4);
            this.groupBox8.Controls.Add(this.buttonStop);
            this.groupBox8.Controls.Add(this.buttonDecoding);
            this.groupBox8.Controls.Add(this.buttonCoding);
            this.groupBox8.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.groupBox8.Location = new System.Drawing.Point(13, 552);
            this.groupBox8.Name = "groupBox8";
            this.groupBox8.Size = new System.Drawing.Size(637, 69);
            this.groupBox8.TabIndex = 5;
            this.groupBox8.TabStop = false;
            this.groupBox8.Text = "Дії";
            // 
            // labelTime
            // 
            this.labelTime.AutoSize = true;
            this.labelTime.Location = new System.Drawing.Point(525, 28);
            this.labelTime.Name = "labelTime";
            this.labelTime.Size = new System.Drawing.Size(81, 22);
            this.labelTime.TabIndex = 4;
            this.labelTime.Text = "00:00.00";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(373, 30);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(146, 22);
            this.label4.TabIndex = 3;
            this.label4.Text = "Час розрахунку:";
            // 
            // buttonStop
            // 
            this.buttonStop.Location = new System.Drawing.Point(251, 22);
            this.buttonStop.Name = "buttonStop";
            this.buttonStop.Size = new System.Drawing.Size(116, 34);
            this.buttonStop.TabIndex = 2;
            this.buttonStop.Text = "Зупинити";
            this.buttonStop.UseVisualStyleBackColor = true;
            // 
            // buttonDecoding
            // 
            this.buttonDecoding.Location = new System.Drawing.Point(129, 22);
            this.buttonDecoding.Name = "buttonDecoding";
            this.buttonDecoding.Size = new System.Drawing.Size(116, 34);
            this.buttonDecoding.TabIndex = 1;
            this.buttonDecoding.Text = "Розшифрувати";
            this.buttonDecoding.UseVisualStyleBackColor = true;
            this.buttonDecoding.Click += new System.EventHandler(this.buttonDecoding_Click);
            // 
            // buttonCoding
            // 
            this.buttonCoding.Location = new System.Drawing.Point(7, 22);
            this.buttonCoding.Name = "buttonCoding";
            this.buttonCoding.Size = new System.Drawing.Size(116, 34);
            this.buttonCoding.TabIndex = 0;
            this.buttonCoding.Text = "Зашифрувати";
            this.buttonCoding.UseVisualStyleBackColor = true;
            this.buttonCoding.Click += new System.EventHandler(this.buttonCoding_Click);
            // 
            // menuStrip1
            // 
            this.menuStrip1.Dock = System.Windows.Forms.DockStyle.Right;
            this.menuStrip1.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.довідкаToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(639, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(98, 624);
            this.menuStrip1.TabIndex = 6;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // довідкаToolStripMenuItem
            // 
            this.довідкаToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.проПрограмуToolStripMenuItem,
            this.вихідToolStripMenuItem});
            this.довідкаToolStripMenuItem.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.довідкаToolStripMenuItem.Name = "довідкаToolStripMenuItem";
            this.довідкаToolStripMenuItem.Size = new System.Drawing.Size(85, 26);
            this.довідкаToolStripMenuItem.Text = "Довідка";
            // 
            // проПрограмуToolStripMenuItem
            // 
            this.проПрограмуToolStripMenuItem.Name = "проПрограмуToolStripMenuItem";
            this.проПрограмуToolStripMenuItem.Size = new System.Drawing.Size(213, 26);
            this.проПрограмуToolStripMenuItem.Text = "Про програму";
            this.проПрограмуToolStripMenuItem.Click += new System.EventHandler(this.проПрограмуToolStripMenuItem_Click);
            // 
            // вихідToolStripMenuItem
            // 
            this.вихідToolStripMenuItem.Name = "вихідToolStripMenuItem";
            this.вихідToolStripMenuItem.Size = new System.Drawing.Size(213, 26);
            this.вихідToolStripMenuItem.Text = "Вихід";
            this.вихідToolStripMenuItem.Click += new System.EventHandler(this.вихідToolStripMenuItem_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 19F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(737, 624);
            this.Controls.Add(this.groupBox8);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.groupBox3);
            this.Controls.Add(this.menuStrip1);
            this.Font = new System.Drawing.Font("Times New Roman", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.menuStrip1;
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MaximumSize = new System.Drawing.Size(755, 671);
            this.MinimumSize = new System.Drawing.Size(755, 671);
            this.Name = "Form1";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Блокові шифри";
            this.groupBox3.ResumeLayout(false);
            this.groupBox5.ResumeLayout(false);
            this.groupBox5.PerformLayout();
            this.groupBox4.ResumeLayout(false);
            this.groupBox4.PerformLayout();
            this.groupBox1.ResumeLayout(false);
            this.groupBox7.ResumeLayout(false);
            this.panel2.ResumeLayout(false);
            this.panel2.PerformLayout();
            this.groupBox6.ResumeLayout(false);
            this.groupBox6.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.groupBox8.ResumeLayout(false);
            this.groupBox8.PerformLayout();
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBox3;
        private System.Windows.Forms.GroupBox groupBox5;
        private System.Windows.Forms.Label labelFileOUTLength;
        private System.Windows.Forms.Label labelEntropyFileOUT;
        private System.Windows.Forms.Button button_fileOUT;
        private System.Windows.Forms.TextBox textBox_fileOUT;
        private System.Windows.Forms.GroupBox groupBox4;
        private System.Windows.Forms.Label labelFileINLength;
        private System.Windows.Forms.Label labelEntropyFileIN;
        private System.Windows.Forms.Button button_fileIN;
        private System.Windows.Forms.TextBox textBox_fileIN;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.GroupBox groupBox7;
        private System.Windows.Forms.Panel panel2;
        private System.Windows.Forms.RadioButton radioButtonRC2;
        private System.Windows.Forms.RadioButton radioButtonTripleDES;
        private System.Windows.Forms.RadioButton radioButtonDES;
        private System.Windows.Forms.RadioButton radioButtonRijndeal;
        private System.Windows.Forms.RadioButton radioButtonAES;
        private System.Windows.Forms.GroupBox groupBox6;
        private System.Windows.Forms.Button buttonIVKeyGen;
        private System.Windows.Forms.TextBox textBoxIVector;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.Button buttonKeyGen;
        private System.Windows.Forms.TextBox textBoxKeyGen;
        private System.Windows.Forms.Button button_fileKeyUpdate;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.Button button_fileKeyOUT;
        private System.Windows.Forms.ComboBox comboBoxTypeFilling;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.ComboBox comboBoxCipher;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.ComboBox comboBox_keyLength_bit;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.GroupBox groupBox8;
        private System.Windows.Forms.Label labelTime;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Button buttonStop;
        private System.Windows.Forms.Button buttonDecoding;
        private System.Windows.Forms.Button buttonCoding;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem довідкаToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem проПрограмуToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem вихідToolStripMenuItem;
        private System.Windows.Forms.CheckBox checkBoxIVector;
        private System.Windows.Forms.ToolTip toolTip1;
    }
}

