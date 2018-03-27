from tkinter import *
from tkinter import ttk, messagebox, filedialog, scrolledtext
from os.path import isfile
import rsa
import time


class Window:
    def __init__(self, master):
        # initialize frame
        self.top_frame = Frame(master=master)
        self.top_frame.pack(expand=TRUE, fill=BOTH)

        self.bottom_frame = Frame(master=master)
        self.bottom_frame.pack(fill=BOTH, side=BOTTOM)

        # initialize tabbed widgets
        self.initialize_tabbed_widgets()

        # Component for tab key-generator
        self.initialize_key_generator()

        # Component for tab encryption
        self.initialize_encryption()

        # Component for tab decryption
        self.initialize_decryption()

        # Bottom_Frame
        quit_button = Button(self.bottom_frame, text='Quit', command=master.destroy)
        quit_button.pack(side=RIGHT, padx=5)

    def initialize_tabbed_widgets(self):
        self.tab_menu = ttk.Notebook(self.top_frame)

        # initialize the individual tab menu
        self.tab_key_generator = ttk.Frame(self.tab_menu)
        self.tab_encrypt = ttk.Frame(self.tab_menu)
        self.tab_decrypt = ttk.Frame(self.tab_menu)

        # add individual tab menu into tabbed widgets
        self.tab_menu.add(self.tab_key_generator, text='Key Generator')
        self.tab_menu.add(self.tab_encrypt, text='RSA-Encryption')
        self.tab_menu.add(self.tab_decrypt, text='RSA-Decryption')

        # show tabbed widgets
        self.tab_menu.pack(expand=1, fill="both")

    # ALL ABOUT KEY GENERATOR TAB
    def initialize_key_generator(self):
        frame_key_generator = Frame(self.tab_key_generator)
        frame_key_generator.place(anchor='nw', relx=0.05, rely=0.05)

        # LABEL TEXT
        length_label_p = Label(frame_key_generator, text="Length p: ")
        length_label_p.grid(row=0, column=0, padx=5, pady=2.5)

        length_label_q = Label(frame_key_generator, text="Length q: ")
        length_label_q.grid(row=1, column=0, padx=5, pady=2.5)

        public_key_label = Label(frame_key_generator, text="Public Keys: ")
        public_key_label.grid(row=3, column=0, padx=5, pady=10)

        private_key_label = Label(frame_key_generator, text="Private Keys: ")
        private_key_label.grid(row=6, column=0, padx=5, pady=10)

        # USER INPUT
        self.random_length_entry_p = Entry(frame_key_generator, width=10)
        self.random_length_entry_p.grid(row=0, column=1, padx=5, pady=2.5)

        self.random_length_entry_q = Entry(frame_key_generator, width=10)
        self.random_length_entry_q.grid(row=1, column=1, padx=5, pady=2.5)

        self.public_key_e_entry = Entry(frame_key_generator, width=70)
        self.public_key_e_entry.grid(row=3, column=1, padx=5, pady=2.5, columnspan=5)

        self.public_key_n_entry = Entry(frame_key_generator, width=70)
        self.public_key_n_entry.grid(row=4, column=1, padx=5, pady=2.5, columnspan=5)

        self.private_key_d_entry = Entry(frame_key_generator, width=70)
        self.private_key_d_entry.grid(row=6, column=1, padx=5, pady=2.5, columnspan=5)

        self.private_key_n_entry = Entry(frame_key_generator, width=70)
        self.private_key_n_entry.grid(row=7, column=1, padx=5, pady=2.5, columnspan=5)

        # BUTTON
        generate_key_button = Button(frame_key_generator, text="Generate Keys", command=self.generate_keys)
        generate_key_button.grid(row=2, column=0, padx=5, pady=5)

        save_public_button = Button(frame_key_generator, text="Save Public Keys", command=self.save_public_keys)
        save_public_button.grid(row=5, column=1, padx=5, pady=2.5)

        save_private_button = Button(frame_key_generator, text="Save Private Keys", command=self.save_private_keys)
        save_private_button.grid(row=8, column=1, padx=5, pady=2.5)

    def generate_keys(self):
        try:
            if not self.random_length_entry_p.get() or not self.random_length_entry_q.get():
                raise Exception('Please specify the length of p and q')
            if not self.random_length_entry_p.get().isdigit() or not self.random_length_entry_q.get().isdigit():
                raise Exception('The length must be an integer')
            if int(self.random_length_entry_p.get()) <= 0 or int(self.random_length_entry_q.get()) <= 0:
                raise Exception('The length must larger than zero')

            cipher = rsa.RSA()
            p = cipher.generate_prime(length=int(self.random_length_entry_p.get()))
            q = cipher.generate_prime(length=int(self.random_length_entry_q.get()))
            public_keys, private_keys = cipher.generate_keys(p, q)

            self.public_key_e_entry.delete(0, END)
            self.public_key_n_entry.delete(0, END)
            self.private_key_d_entry.delete(0, END)
            self.private_key_n_entry.delete(0, END)

            self.public_key_e_entry.insert(0, str(public_keys[0]))
            self.public_key_n_entry.insert(0, str(public_keys[1]))
            self.private_key_d_entry.insert(0, str(private_keys[0]))
            self.private_key_n_entry.insert(0, str(private_keys[1]))

        except Exception as e:
            messagebox.showerror('Exception Caught', str(e))

    def save_public_keys(self):
        f = filedialog.asksaveasfile(initialdir="/", title="Select File",
                                     mode='w', defaultextension=".rpub",
                                     filetypes=(("rsa public keys", "*.rpub"), ("all files", "*.*")))
        if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
            return
        text2save = self.public_key_e_entry.get() + "," + self.public_key_n_entry.get()
        f.write(text2save)
        f.close()

    def save_private_keys(self):
        f = filedialog.asksaveasfile(initialdir="/", title="Select File",
                                     mode='w', defaultextension=".rpri",
                                     filetypes=(("rsa private keys", "*.rpri"), ("all files", "*.*")))
        if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
            return
        text2save = self.private_key_d_entry.get() + "," + self.private_key_n_entry.get()
        f.write(text2save)
        f.close()

    # ALL ABOUT ENCRYPTION
    def initialize_encryption(self):
        frame_encryption = Frame(self.tab_encrypt)
        frame_encryption.place(anchor='nw', relx=0.05, rely=0)

        # Label
        plaintext_label = Label(frame_encryption, text="Plaintext: ")
        plaintext_label.grid(row=0, column=0, padx=5, pady=2.5)

        public_keys_label = Label(frame_encryption, text="Public Keys: ")
        public_keys_label.grid(row=1, column=0, padx=5, pady=2.5)

        encryption_result_label = Label(frame_encryption, text="Result: ")
        encryption_result_label.grid(row=3, column=0, padx=5, pady=2.5)

        # Entry
        self.plaintext_entry = Entry(frame_encryption, width=50)
        self.plaintext_entry.grid(row=0, column=1, padx=5, pady=2.5)

        self.public_keys_entry = Entry(frame_encryption, width=50)
        self.public_keys_entry.grid(row=1, column=1, padx=5, pady=2.5)

        # message
        self.encryption_result_message = scrolledtext.ScrolledText(frame_encryption, width=60, height=10)
        self.encryption_result_message.grid(row=4, column=0, padx=5, pady=2.5, columnspan=20)

        # Button
        browse_plaintext_button = Button(frame_encryption, text="Browse", command=self.browse_plaintext)
        browse_plaintext_button.grid(row=0, column=2, padx=5, pady=2.5)

        browse_pubkey_button = Button(frame_encryption, text="Browse", command=self.browse_public_keys)
        browse_pubkey_button.grid(row=1, column=2, padx=5, pady=2.5)

        encrypt_button = Button(frame_encryption, text="Encrypt", command=self.encrypt)
        encrypt_button.grid(row=2, column=0, padx=5, pady=2.5)

        save_encrypted_button = Button(frame_encryption, text="Save", command=self.save_encrypted)
        save_encrypted_button.grid(row=5, column=0, padx=5, pady=2.5)

    def browse_plaintext(self):
        f = filedialog.askopenfilename(initialdir="/", title="Select file")
        self.plaintext_entry.delete(0, END)
        self.plaintext_entry.insert(0, f)

    def browse_public_keys(self):
        f = filedialog.askopenfilename(initialdir="/", title="Select file")
        self.public_keys_entry.delete(0, END)
        self.public_keys_entry.insert(0, f)

    def encrypt(self):
        plaintext_path = self.plaintext_entry.get()
        key_path = self.public_keys_entry.get()

        try:
            if len(plaintext_path) == 0 or len(key_path) == 0:
                raise Exception("Please select the plaintext and public key !")
            if not isfile(plaintext_path) or not isfile(key_path):
                raise Exception("Cannot find the specified file !")

            # Do Encryption here
            with open(key_path, 'r') as infile:
                key = infile.read()
            public_key = int(key.split(',')[0]), int(key.split(',')[1])

            cipher = rsa.RSA()
            start = time.clock()
            result = cipher.encrypt(plaintext_path, public_key)
            end = time.clock()
            self.result_string = " ".join([hex(x) for x in result])

            self.encryption_result_message.delete(1.0, END)
            self.encryption_result_message.insert(INSERT, self.result_string)

            summary = "Elapsed = " + str(end-start) + " seconds\n"
            summary += "File Size = " + str(len(self.result_string) + 2) + " bytes"
            messagebox.showinfo("Summary", summary)

        except Exception as e:
            messagebox.showerror('Exception Caught', str(e))

    def save_encrypted(self):
        f = filedialog.asksaveasfile(initialdir="/", title="Select File",
                                     mode='w', defaultextension=".rsa",
                                     filetypes=(("RSA File", "*.rsa"), ("all files", "*.*")))
        if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
            return
        text2save = self.result_string
        f.write(text2save)
        f.close()

    # ALL ABOUT DECRYPTION
    def initialize_decryption(self):
        frame_decryption = Frame(self.tab_decrypt)
        frame_decryption.place(anchor='nw', relx=0.05, rely=0)

        # Label
        ciphertext_label = Label(frame_decryption, text="Ciphertext: ")
        ciphertext_label.grid(row=0, column=0, padx=5.0, pady=2.5)

        private_keys_label = Label(frame_decryption, text="Private Keys: ")
        private_keys_label.grid(row=1, column=0, padx=5.0, pady=2.5)

        decryption_result_label = Label(frame_decryption, text="Result: ")
        decryption_result_label.grid(row=3, column=0, padx=5, pady=2.5)

        # Entry
        self.ciphertext_entry = Entry(frame_decryption, width=50)
        self.ciphertext_entry.grid(row=0, column=1, padx=5.0, pady=2.5)

        self.private_keys_entry = Entry(frame_decryption, width=50)
        self.private_keys_entry.grid(row=1, column=1, padx=5.0, pady=2.5)

        # message
        self.decryption_result_message = scrolledtext.ScrolledText(frame_decryption, width=60, height=10)
        self.decryption_result_message.grid(row=4, column=0, padx=5, pady=2.5, columnspan=20)

        # Button
        browse_ciphertext_button = Button(frame_decryption, text="Browse", command=self.browse_ciphertext)
        browse_ciphertext_button.grid(row=0, column=2, padx=5.0, pady=2.5)

        browse_prikey_button = Button(frame_decryption, text="Browse", command=self.browse_private_keys)
        browse_prikey_button.grid(row=1, column=2, padx=5.0, pady=2.5)

        decrypt_button = Button(frame_decryption, text="Decrypt", command=self.decrypt)
        decrypt_button.grid(row=2, column=0, padx=5.0, pady=2.5)

        save_decrypted_button = Button(frame_decryption, text="Save", command=self.save_decrypted)
        save_decrypted_button.grid(row=5, column=0, padx=5, pady=2.5)

    def browse_ciphertext(self):
        f = filedialog.askopenfilename(initialdir="/", title="Select file")
        self.ciphertext_entry.delete(0, END)
        self.ciphertext_entry.insert(0, f)

    def browse_private_keys(self):
        f = filedialog.askopenfilename(initialdir="/", title="Select file")
        self.private_keys_entry.delete(0, END)
        self.private_keys_entry.insert(0, f)

    def decrypt(self):
        cipher_path = self.ciphertext_entry.get()
        key_path = self.private_keys_entry.get()

        try:
            if len(cipher_path) == 0 or len(key_path) == 0:
                raise Exception("Please select the ciphertext and private key !")
            if not isfile(cipher_path) or not isfile(key_path):
                raise Exception("Cannot find the specified file !")

            with open(key_path, 'r') as infile:
                key = infile.read()
            private_key = int(key.split(",")[0]), int(key.split(",")[1])

            # Do the decryption here
            cipher = rsa.RSA()
            start = time.clock()
            result = cipher.decrypt(cipher_path, private_key)
            end = time.clock()
            result_string = "".join(chr(x) for x in result)

            self.decryption_result_message.delete(1.0, END)
            self.decryption_result_message.insert(INSERT, result_string)

            summary = "Elapsed = " + str(end - start) + " seconds\n"
            summary += "File Size = " + str(len(result_string)) + " bytes"
            messagebox.showinfo("Summary", summary)

        except Exception as e:
            messagebox.showerror("Exception Caught!", str(e))

    def save_decrypted(self):
        f = filedialog.asksaveasfile(initialdir="/", title="Select File", mode='wb')
        if f is None:
            return
        text2save = [(ord(x)) for x in self.decryption_result_message.get(1.0, END)]
        f.write(bytes(text2save))
        f.close()


root = Tk()
root.geometry('600x400')
root.title("RSA-Algorithm")
window = Window(root)
root.mainloop()
