from tkinter import *
from tkinter import ttk, messagebox, filedialog
import rsa


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

            self.public_key_e_entry.insert(0, str(public_keys[0]))
            self.public_key_n_entry.insert(0, str(public_keys[1]))
            self.private_key_d_entry.insert(0, str(private_keys[0]))
            self.private_key_n_entry.insert(0, str(private_keys[1]))

        except Exception as e:
            messagebox.showerror('Exception Caught', str(e))

    def save_public_keys(self):
        f = filedialog.asksaveasfile(initialdir="/", title="Select File",
                                     mode='w', defaultextension=".pub",
                                     filetypes=(("public keys", "*.pub"), ("all files", "*.*")))
        if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
            return
        text2save = self.public_key_e_entry.get() + "," + self.public_key_n_entry.get()
        f.write(text2save)
        f.close()

    def save_private_keys(self):
        f = filedialog.asksaveasfile(initialdir="/", title="Select File",
                                     mode='w', defaultextension=".pri",
                                     filetypes=(("private keys", "*.pri"), ("all files", "*.*")))
        if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
            return
        text2save = self.private_key_d_entry.get() + "," + self.private_key_n_entry.get()
        f.write(text2save)
        f.close()


root = Tk()
root.geometry('600x400')
root.title("RSA-Algorithm")
window = Window(root)
root.mainloop()
