namespace RutokenAuthorize
{
    partial class AuthorizeWindow
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
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
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            find_keys_button = new Button();
            logTextBox = new RichTextBox();
            password_textbox = new MaskedTextBox();
            label1 = new Label();
            create_keys_button = new Button();
            ID_textbox = new MaskedTextBox();
            label2 = new Label();
            verify_button = new Button();
            modulus_textbox = new MaskedTextBox();
            exponent_textbox = new MaskedTextBox();
            label3 = new Label();
            label4 = new Label();
            SuspendLayout();
            // 
            // find_keys_button
            // 
            find_keys_button.Location = new Point(37, 317);
            find_keys_button.Name = "find_keys_button";
            find_keys_button.Size = new Size(75, 57);
            find_keys_button.TabIndex = 1;
            find_keys_button.Text = "show all available keypairs\r\n";
            find_keys_button.UseVisualStyleBackColor = true;
            find_keys_button.Click += find_keys_button_Click;
            // 
            // logTextBox
            // 
            logTextBox.Location = new Point(166, 12);
            logTextBox.Name = "logTextBox";
            logTextBox.Size = new Size(449, 257);
            logTextBox.TabIndex = 2;
            logTextBox.Text = "";
            // 
            // password_textbox
            // 
            password_textbox.Location = new Point(12, 66);
            password_textbox.Name = "password_textbox";
            password_textbox.PasswordChar = '*';
            password_textbox.Size = new Size(100, 23);
            password_textbox.TabIndex = 3;
            password_textbox.Text = "12345678";
            password_textbox.MaskInputRejected += maskedTextBox1_MaskInputRejected;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(24, 35);
            label1.Name = "label1";
            label1.Size = new Size(70, 15);
            label1.TabIndex = 4;
            label1.Text = "rutoken PIN";
            // 
            // create_keys_button
            // 
            create_keys_button.Location = new Point(144, 317);
            create_keys_button.Name = "create_keys_button";
            create_keys_button.Size = new Size(75, 57);
            create_keys_button.TabIndex = 5;
            create_keys_button.Text = "create new keypair";
            create_keys_button.UseVisualStyleBackColor = true;
            create_keys_button.Click += create_keys_button_Click;
            // 
            // ID_textbox
            // 
            ID_textbox.Location = new Point(225, 342);
            ID_textbox.Name = "ID_textbox";
            ID_textbox.Size = new Size(100, 23);
            ID_textbox.TabIndex = 6;
            ID_textbox.Text = "LICENSE";
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(225, 326);
            label2.Name = "label2";
            label2.Size = new Size(59, 15);
            label2.TabIndex = 7;
            label2.Text = "keypair ID";
            // 
            // verify_button
            // 
            verify_button.Location = new Point(375, 317);
            verify_button.Name = "verify_button";
            verify_button.Size = new Size(75, 57);
            verify_button.TabIndex = 8;
            verify_button.Text = "verify keypair";
            verify_button.UseVisualStyleBackColor = true;
            verify_button.Click += verify_button_Click;
            // 
            // modulus_textbox
            // 
            modulus_textbox.Location = new Point(466, 317);
            modulus_textbox.Name = "modulus_textbox";
            modulus_textbox.Size = new Size(100, 23);
            modulus_textbox.TabIndex = 9;
            // 
            // exponent_textbox
            // 
            exponent_textbox.Location = new Point(466, 364);
            exponent_textbox.Name = "exponent_textbox";
            exponent_textbox.Size = new Size(100, 23);
            exponent_textbox.TabIndex = 10;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new Point(466, 299);
            label3.Name = "label3";
            label3.Size = new Size(54, 15);
            label3.TabIndex = 11;
            label3.Text = "modulus";
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new Point(466, 346);
            label4.Name = "label4";
            label4.Size = new Size(57, 15);
            label4.TabIndex = 12;
            label4.Text = "exponent";
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(800, 450);
            Controls.Add(label4);
            Controls.Add(label3);
            Controls.Add(exponent_textbox);
            Controls.Add(modulus_textbox);
            Controls.Add(verify_button);
            Controls.Add(label2);
            Controls.Add(ID_textbox);
            Controls.Add(create_keys_button);
            Controls.Add(label1);
            Controls.Add(password_textbox);
            Controls.Add(logTextBox);
            Controls.Add(find_keys_button);
            Name = "Form1";
            Text = "Form1";
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion
        private Button find_keys_button;
        private RichTextBox logTextBox;
        private MaskedTextBox password_textbox;
        private Label label1;
        private Button create_keys_button;
        private MaskedTextBox ID_textbox;
        private Label label2;
        private Button verify_button;
        private MaskedTextBox modulus_textbox;
        private MaskedTextBox exponent_textbox;
        private Label label3;
        private Label label4;
    }
}
