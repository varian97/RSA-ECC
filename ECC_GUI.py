from tkinter import *
from tkinter import ttk, filedialog, messagebox
import ECC
from Point import Point


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


root = Tk()
root.geometry('600x400')
root.title("ECC-Algorithm")
window = Window(root)
root.mainloop()