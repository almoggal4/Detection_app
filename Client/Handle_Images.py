import tkinter as tk


class GalleryScroll(tk.Frame):
    def __init__(self, parent, images):
        tk.Frame.__init__(self, parent)
        text = tk.Text(self, wrap="none", bg='#%02x%02x%02x' % (246, 219, 80))
        vsb = tk.Scrollbar(parent, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=vsb.set, bg='#%02x%02x%02x' % (246, 219, 80))
        vsb.pack(side="right", fill="y")
        text.pack(fill="both", expand=True)

        for image in images:

            photo = tk.PhotoImage(file=image)
            photo = photo.subsample(2)

            b = tk.Label(self, image=photo)
            b.image = photo  # keep a reference
            text.window_create("end", window=b)
            text.insert("end", "\n")

        text.configure(state="disabled")


class Picture(tk.Frame):
    def __init__(self, parent, image):
        tk.Frame.__init__(self, parent)
        text = tk.Text(self, wrap="none", bg='#%02x%02x%02x' % (246, 219, 80))
        text.configure(bg='#%02x%02x%02x' % (246, 219, 80))
        text.pack(fill="both", expand=True)
        photo = tk.PhotoImage(file=image)
        photo = photo.subsample(1)  # size and angle of picture

        b = tk.Label(self, image=photo)
        b.image = photo  # keep a reference
        text.window_create("end", window=b)
        text.insert("end", "\n")

        text.configure(state="disabled")
