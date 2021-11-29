
namespace Laba7
{
    partial class Form2
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form2));
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.labelEmail = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.linkLabel_RC2 = new System.Windows.Forms.LinkLabel();
            this.linkLabel_TriplDES = new System.Windows.Forms.LinkLabel();
            this.linkLabel_DES = new System.Windows.Forms.LinkLabel();
            this.linkLabel_Rijndael = new System.Windows.Forms.LinkLabel();
            this.linkLabel_AES = new System.Windows.Forms.LinkLabel();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.pictureBox2 = new System.Windows.Forms.PictureBox();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.buttonClose = new System.Windows.Forms.Button();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox2)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.SuspendLayout();
            // 
            // textBox1
            // 
            this.textBox1.Location = new System.Drawing.Point(392, 127);
            this.textBox1.Margin = new System.Windows.Forms.Padding(4);
            this.textBox1.Name = "textBox1";
            this.textBox1.ReadOnly = true;
            this.textBox1.Size = new System.Drawing.Size(201, 22);
            this.textBox1.TabIndex = 7;
            this.textBox1.Text = "4002232@stud.nau.edu.ua";
            this.textBox1.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // labelEmail
            // 
            this.labelEmail.AutoSize = true;
            this.labelEmail.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.labelEmail.Location = new System.Drawing.Point(323, 129);
            this.labelEmail.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.labelEmail.Name = "labelEmail";
            this.labelEmail.Size = new System.Drawing.Size(63, 22);
            this.labelEmail.TabIndex = 6;
            this.labelEmail.Text = "Email:";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.label1.Location = new System.Drawing.Point(321, 91);
            this.label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(281, 22);
            this.label1.TabIndex = 5;
            this.label1.Text = "Автор: Кравець Валерій, 2021р.";
            // 
            // linkLabel_RC2
            // 
            this.linkLabel_RC2.AutoSize = true;
            this.linkLabel_RC2.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.linkLabel_RC2.Location = new System.Drawing.Point(159, 352);
            this.linkLabel_RC2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.linkLabel_RC2.Name = "linkLabel_RC2";
            this.linkLabel_RC2.Size = new System.Drawing.Size(46, 22);
            this.linkLabel_RC2.TabIndex = 21;
            this.linkLabel_RC2.TabStop = true;
            this.linkLabel_RC2.Text = "RC2";
            this.linkLabel_RC2.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkLabel_RC2_LinkClicked);
            // 
            // linkLabel_TriplDES
            // 
            this.linkLabel_TriplDES.AutoSize = true;
            this.linkLabel_TriplDES.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.linkLabel_TriplDES.Location = new System.Drawing.Point(199, 393);
            this.linkLabel_TriplDES.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.linkLabel_TriplDES.Name = "linkLabel_TriplDES";
            this.linkLabel_TriplDES.Size = new System.Drawing.Size(87, 22);
            this.linkLabel_TriplDES.TabIndex = 20;
            this.linkLabel_TriplDES.TabStop = true;
            this.linkLabel_TriplDES.Text = "TriplDES";
            this.linkLabel_TriplDES.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkLabel_TriplDES_LinkClicked);
            // 
            // linkLabel_DES
            // 
            this.linkLabel_DES.AutoSize = true;
            this.linkLabel_DES.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.linkLabel_DES.Location = new System.Drawing.Point(235, 352);
            this.linkLabel_DES.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.linkLabel_DES.Name = "linkLabel_DES";
            this.linkLabel_DES.Size = new System.Drawing.Size(47, 22);
            this.linkLabel_DES.TabIndex = 19;
            this.linkLabel_DES.TabStop = true;
            this.linkLabel_DES.Text = "DES";
            this.linkLabel_DES.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkLabel_DES_LinkClicked);
            // 
            // linkLabel_Rijndael
            // 
            this.linkLabel_Rijndael.AutoSize = true;
            this.linkLabel_Rijndael.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.linkLabel_Rijndael.Location = new System.Drawing.Point(68, 393);
            this.linkLabel_Rijndael.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.linkLabel_Rijndael.Name = "linkLabel_Rijndael";
            this.linkLabel_Rijndael.Size = new System.Drawing.Size(78, 22);
            this.linkLabel_Rijndael.TabIndex = 18;
            this.linkLabel_Rijndael.TabStop = true;
            this.linkLabel_Rijndael.Text = "Rijndael";
            this.linkLabel_Rijndael.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkLabel_Rijndael_LinkClicked);
            // 
            // linkLabel_AES
            // 
            this.linkLabel_AES.AutoSize = true;
            this.linkLabel_AES.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.linkLabel_AES.Location = new System.Drawing.Point(68, 352);
            this.linkLabel_AES.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.linkLabel_AES.Name = "linkLabel_AES";
            this.linkLabel_AES.Size = new System.Drawing.Size(47, 22);
            this.linkLabel_AES.TabIndex = 17;
            this.linkLabel_AES.TabStop = true;
            this.linkLabel_AES.Text = "AES";
            this.linkLabel_AES.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.linkLabel_AES_LinkClicked);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.label2.Location = new System.Drawing.Point(16, 313);
            this.label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(163, 22);
            this.label2.TabIndex = 16;
            this.label2.Text = "в .NET Framework";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.label3.Location = new System.Drawing.Point(16, 278);
            this.label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(303, 22);
            this.label3.TabIndex = 15;
            this.label3.Text = "алгоритми шифрування, вбудовані";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.label4.Location = new System.Drawing.Point(16, 244);
            this.label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(316, 22);
            this.label4.TabIndex = 14;
            this.label4.Text = "Програма використовує симетричні";
            // 
            // pictureBox2
            // 
            this.pictureBox2.BackgroundImageLayout = System.Windows.Forms.ImageLayout.None;
            this.pictureBox2.Image = global::Laba7.Properties.Resources.sharp;
            this.pictureBox2.Location = new System.Drawing.Point(365, 244);
            this.pictureBox2.Margin = new System.Windows.Forms.Padding(4);
            this.pictureBox2.Name = "pictureBox2";
            this.pictureBox2.Size = new System.Drawing.Size(277, 244);
            this.pictureBox2.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.pictureBox2.TabIndex = 13;
            this.pictureBox2.TabStop = false;
            // 
            // pictureBox1
            // 
            this.pictureBox1.BackgroundImageLayout = System.Windows.Forms.ImageLayout.None;
            this.pictureBox1.Image = global::Laba7.Properties.Resources.github;
            this.pictureBox1.Location = new System.Drawing.Point(16, 15);
            this.pictureBox1.Margin = new System.Windows.Forms.Padding(4);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(259, 213);
            this.pictureBox1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.pictureBox1.TabIndex = 4;
            this.pictureBox1.TabStop = false;
            // 
            // buttonClose
            // 
            this.buttonClose.Font = new System.Drawing.Font("Times New Roman", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.buttonClose.Location = new System.Drawing.Point(124, 455);
            this.buttonClose.Margin = new System.Windows.Forms.Padding(4);
            this.buttonClose.Name = "buttonClose";
            this.buttonClose.Size = new System.Drawing.Size(100, 32);
            this.buttonClose.TabIndex = 22;
            this.buttonClose.Text = "ОК";
            this.buttonClose.UseVisualStyleBackColor = true;
            this.buttonClose.Click += new System.EventHandler(this.buttonClose_Click);
            // 
            // Form2
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(659, 502);
            this.Controls.Add(this.buttonClose);
            this.Controls.Add(this.linkLabel_RC2);
            this.Controls.Add(this.linkLabel_TriplDES);
            this.Controls.Add(this.linkLabel_DES);
            this.Controls.Add(this.linkLabel_Rijndael);
            this.Controls.Add(this.linkLabel_AES);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.pictureBox2);
            this.Controls.Add(this.textBox1);
            this.Controls.Add(this.labelEmail);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.pictureBox1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MaximumSize = new System.Drawing.Size(677, 549);
            this.MinimumSize = new System.Drawing.Size(677, 549);
            this.Name = "Form2";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Про блокові шифри";
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox2)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox textBox1;
        private System.Windows.Forms.Label labelEmail;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.PictureBox pictureBox1;
        private System.Windows.Forms.LinkLabel linkLabel_RC2;
        private System.Windows.Forms.LinkLabel linkLabel_TriplDES;
        private System.Windows.Forms.LinkLabel linkLabel_DES;
        private System.Windows.Forms.LinkLabel linkLabel_Rijndael;
        private System.Windows.Forms.LinkLabel linkLabel_AES;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.PictureBox pictureBox2;
        private System.Windows.Forms.Button buttonClose;
    }
}