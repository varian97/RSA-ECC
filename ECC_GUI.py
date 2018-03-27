from tkinter import *
from tkinter import ttk, filedialog, messagebox, scrolledtext
import ECC
from Point import Point
from os.path import isfile
import time


def check_int(s):
    if s[0] in ('-', '+'):
        return s[1:].isdigit()
    return s.isdigit()


class Window:
    def __init__(self, master):
        # initialize frame
        self.top_frame = Frame(master=master)
        self.top_frame.pack(expand=TRUE, fill=BOTH)

        self.bottom_frame = Frame(master=master)
        self.bottom_frame.pack(fill=BOTH, side=BOTTOM)

        # initialize tabbed widgets
        self.initialize_tabbed_widgets()

        # component for key generator tab
        self.initialize_key_generator()

        # component for encryption tab
        self.initialize_encryption()

        # Component for decryption tab
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
        self.tab_menu.add(self.tab_encrypt, text='ECC-Encryption')
        self.tab_menu.add(self.tab_decrypt, text='ECC-Decryption')

        # show tabbed widgets
        self.tab_menu.pack(expand=1, fill="both")

    # ALL ABOUT KEY GENERATOR
    def initialize_key_generator(self):
        frame_key_generator = Frame(self.tab_key_generator)
        frame_key_generator.place(anchor='nw', relx=0.05, rely=0.05)

        # LABEL
        label_a = Label(frame_key_generator, text="a :")
        label_a.grid(row= 0, column=0, padx=5, pady=2.5)

        label_b = Label(frame_key_generator, text="b :")
        label_b.grid(row=0, column=2, padx=5, pady=2.5)

        label_p = Label(frame_key_generator, text="p :")
        label_p.grid(row=0, column=4, padx=5, pady=2.5)

        label_x = Label(frame_key_generator, text="x :")
        label_x.grid(row=1, column=0, padx=5, pady=2.5)

        label_y = Label(frame_key_generator, text="y :")
        label_y.grid(row=1, column=2, padx=5, pady=2.5)

        public_key_label = Label(frame_key_generator, text="Public Key: ")
        public_key_label.grid(row=3, column=0, padx=5, pady=2.5)

        private_key_label = Label(frame_key_generator, text="Private Key: ")
        private_key_label.grid(row=4, column=0, padx=5, pady=2.5)

        # ENTRY
        self.a_entry = Entry(frame_key_generator, width=10)
        self.a_entry.grid(row=0, column=1, padx=5, pady=2.5)

        self.b_entry = Entry(frame_key_generator, width=10)
        self.b_entry.grid(row=0, column=3, padx=5, pady=2.5)

        self.p_entry = Entry(frame_key_generator, width=10)
        self.p_entry.grid(row=0, column=5, padx=5, pady=2.5)

        self.x_entry = Entry(frame_key_generator, width=10)
        self.x_entry.grid(row=1, column=1, padx=5, pady=2.5)

        self.y_entry = Entry(frame_key_generator, width=10)
        self.y_entry.grid(row=1, column=3, padx=5, pady=2.5)

        self.public_key_entry_x = Entry(frame_key_generator, width=10)
        self.public_key_entry_x.grid(row=3, column=1, padx=5, pady=2.5)

        self.public_key_entry_y = Entry(frame_key_generator, width=10)
        self.public_key_entry_y.grid(row=3, column=2, padx=5, pady=2.5)

        self.private_key_entry = Entry(frame_key_generator, width=20)
        self.private_key_entry.grid(row=4, column=1, padx=5, pady=2.5, columnspan=2)

        # BUTTON
        generate_key_button = Button(frame_key_generator, text="Generate Keys", command=self.generate_key)
        generate_key_button.grid(row=2, column=0, padx=5, pady=5)

        save_pubkey_button = Button(frame_key_generator, text="Save", command=self.save_public_key)
        save_pubkey_button.grid(row=3, column=3, padx=5, pady=2.5)

        save_prikey_button = Button(frame_key_generator, text="Save", command=self.save_private_key)
        save_prikey_button.grid(row=4, column=3, padx=5, pady=2.5)

    def generate_key(self):
        try:
            if not self.a_entry.get() or not self.b_entry.get() or not self.p_entry.get() or not self.x_entry.get() \
                    or not self.y_entry.get():
                raise Exception("Please fill all the fields!")
            if not check_int(self.a_entry.get()) or not check_int(self.b_entry.get()) or not check_int(self.p_entry.get()) \
                    or not check_int(self.x_entry.get()) or not check_int(self.y_entry.get()):
                raise Exception("All the input must be an integer!")

            a = int(self.a_entry.get())
            b = int(self.b_entry.get())
            p = int(self.p_entry.get())
            g = Point(int(self.x_entry.get()), int(self.y_entry.get()))

            cipher = ECC.ECCipher(a, b, p, g)
            private_key, public_key = cipher.gen_key_pair()

            self.private_key_entry.insert(0, str(private_key))
            self.public_key_entry_x.insert(0, str(public_key.X))
            self.public_key_entry_y.insert(0, str(public_key.Y))

        except Exception as e:
            messagebox.showerror("Exception Caught!", str(e))

    def save_public_key(self):
        f = filedialog.asksaveasfile(initialdir="/", title="Select File",
                                     mode='w', defaultextension=".epub",
                                     filetypes=(("ecc public key", "*.epub"), ("all files", "*.*")))
        if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
            return
        text2save = self.a_entry.get() + "|" + self.b_entry.get() + "|" + self.p_entry.get() + "|" + \
                    self.x_entry.get() + "|" + self.y_entry.get() + "|" + self.public_key_entry_x.get() + "|" + \
                    self.public_key_entry_y.get()
        f.write(text2save)
        f.close()

    def save_private_key(self):
        f = filedialog.asksaveasfile(initialdir="/", title="Select File",
                                     mode='w', defaultextension=".epri",
                                     filetypes=(("ecc private key", "*.epri"), ("all files", "*.*")))
        if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
            return
        text2save = self.a_entry.get() + "|" + self.b_entry.get() + "|" + self.p_entry.get() + "|" + \
                    self.x_entry.get() + "|" + self.y_entry.get() + "|" + self.private_key_entry.get()
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

        k_label = Label(frame_encryption, text="k: ")
        k_label.grid(row=2, column=0, padx=5, pady=2.5)

        encryption_result_label = Label(frame_encryption, text="Result: ")
        encryption_result_label.grid(row=4, column=0, padx=5, pady=2.5)

        # Entry
        self.plaintext_entry = Entry(frame_encryption, width=50)
        self.plaintext_entry.grid(row=0, column=1, padx=5, pady=2.5)

        self.public_keys_entry = Entry(frame_encryption, width=50)
        self.public_keys_entry.grid(row=1, column=1, padx=5, pady=2.5)

        self.k_entry = Entry(frame_encryption, width=50)
        self.k_entry.grid(row=2, column=1, padx=5, pady=2.5)

        # message
        self.encryption_result_message = scrolledtext.ScrolledText(frame_encryption, width=60, height=9)
        self.encryption_result_message.grid(row=5, column=0, padx=5, pady=2.5, columnspan=20)

        # Button
        browse_plaintext_button = Button(frame_encryption, text="Browse", command=self.browse_plaintext)
        browse_plaintext_button.grid(row=0, column=2, padx=5, pady=2.5)

        browse_pubkey_button = Button(frame_encryption, text="Browse", command=self.browse_public_keys)
        browse_pubkey_button.grid(row=1, column=2, padx=5, pady=2.5)

        encrypt_button = Button(frame_encryption, text="Encrypt", command=self.encrypt)
        encrypt_button.grid(row=3, column=0, padx=5, pady=2.5)

        save_encrypted_button = Button(frame_encryption, text="Save", command=self.save_encrypted)
        save_encrypted_button.grid(row=6, column=0, padx=5, pady=2.5)

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
        k = self.k_entry.get()
        try:
            if len(plaintext_path) == 0 or len(key_path) == 0 or len(k) == 0:
                raise Exception("Please select the plaintext, public key and k!")
            if not isfile(plaintext_path) or not isfile(key_path):
                raise Exception("Cannot find the specified file !")
            if not check_int(k):
                raise Exception("k must be an integer !")

            # do encryption
            with open(plaintext_path, 'rb') as infile:
                content = infile.read()

            with open(key_path, 'r') as infile:
                content_key = infile.read()

            content_key = content_key.split('|')
            a = int(content_key[0])
            b = int(content_key[1])
            p = int(content_key[2])
            g = Point(int(content_key[3]), int(content_key[4]))
            pb = Point(int(content_key[5]), int(content_key[6]))
            k = int(k)

            cipher = ECC.ECCipher(a, b, p, g, k)

            start = time.clock()
            plain_point = cipher.plain_encode(content)
            cipherpoint = cipher.encrypt(plain_point, pb)
            end = time.clock()

            self.ciphertext = cipher.dump_points(cipherpoint)
            ciphertext_for_print = " ".join(hex(x) for x in self.ciphertext)

            self.encryption_result_message.delete(1.0, END)
            self.encryption_result_message.insert(INSERT, ciphertext_for_print)

            summary = "Elapsed = " + str(end - start) + " seconds\n"
            summary += "File Size = " + str(len(ciphertext_for_print) + 2) + " bytes"
            messagebox.showinfo("Summary", summary)

        except Exception as e:
            messagebox.showerror("Exception Caught!", str(e))

    def save_encrypted(self):
        f = filedialog.asksaveasfile(initialdir="/", title="Select File",
                                     mode='wb', defaultextension=".ecc",
                                     filetypes=(("ECC File", "*.ecc"), ("all files", "*.*")))
        if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
            return
        text2save = self.ciphertext
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

        k_label = Label(frame_decryption, text="k: ")
        k_label.grid(row=2, column=0, padx=5.0, pady=2.5)

        decryption_result_label = Label(frame_decryption, text="Result: ")
        decryption_result_label.grid(row=4, column=0, padx=5, pady=2.5)

        # Entry
        self.ciphertext_entry = Entry(frame_decryption, width=50)
        self.ciphertext_entry.grid(row=0, column=1, padx=5.0, pady=2.5)

        self.private_keys_entry = Entry(frame_decryption, width=50)
        self.private_keys_entry.grid(row=1, column=1, padx=5.0, pady=2.5)

        self.k_entry_decryption = Entry(frame_decryption, width=50)
        self.k_entry_decryption.grid(row=2, column=1, padx=5, pady=2.5)

        # message
        self.decryption_result_message = scrolledtext.ScrolledText(frame_decryption, width=60, height=9)
        self.decryption_result_message.grid(row=5, column=0, padx=5, pady=2.5, columnspan=20)

        # Button
        browse_ciphertext_button = Button(frame_decryption, text="Browse", command=self.browse_ciphertext)
        browse_ciphertext_button.grid(row=0, column=2, padx=5.0, pady=2.5)

        browse_prikey_button = Button(frame_decryption, text="Browse", command=self.browse_private_key)
        browse_prikey_button.grid(row=1, column=2, padx=5.0, pady=2.5)

        decrypt_button = Button(frame_decryption, text="Decrypt", command=self.decrypt)
        decrypt_button.grid(row=3, column=0, padx=5.0, pady=2.5)

        save_decrypted_button = Button(frame_decryption, text="Save", command=self.save_decrypted)
        save_decrypted_button.grid(row=6, column=0, padx=5, pady=2.5)

    def browse_ciphertext(self):
        f = filedialog.askopenfilename(initialdir="/", title="Select file")
        self.ciphertext_entry.delete(0, END)
        self.ciphertext_entry.insert(0, f)

    def browse_private_key(self):
        f = filedialog.askopenfilename(initialdir="/", title="Select file")
        self.private_keys_entry.delete(0, END)
        self.private_keys_entry.insert(0, f)

    def decrypt(self):
        cipher_path = self.ciphertext_entry.get()
        key_path = self.private_keys_entry.get()
        k = self.k_entry_decryption.get()

        try:
            if len(cipher_path) == 0 or len(key_path) == 0 or len(k) == 0:
                raise Exception("Please select the ciphertext, private key and k!")
            if not isfile(cipher_path) or not isfile(key_path):
                raise Exception("Cannot find the specified file !")
            if not check_int(k):
                raise Exception("k must be an integer !")

            with open(cipher_path, 'rb') as infile:
                content = infile.read()

            with open(key_path, 'r') as infile:
                content_key = infile.read()

            content_key = content_key.split('|')
            a = int(content_key[0])
            b = int(content_key[1])
            p = int(content_key[2])
            g = Point(int(content_key[3]), int(content_key[4]))
            private_key = int(content_key[5])
            k = int(k)

            cipher = ECC.ECCipher(a, b, p, g, k)
            start = time.clock()
            cipher_point = cipher.load_points(content)
            plain_point = cipher.decrypt(cipher_point, private_key)
            plaintext = cipher.plain_decode(plain_point)
            plaintext = "".join(chr(x) for x in plaintext)
            end = time.clock()

            self.decryption_result_message.delete(1.0, END)
            self.decryption_result_message.insert(INSERT, plaintext)

            summary = "Elapsed = " + str(end - start) + " seconds\n"
            summary += "File Size = " + str(len(plain_point) + 2) + " bytes"
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
root.title("ECC-Algorithm")
window = Window(root)
root.mainloop()