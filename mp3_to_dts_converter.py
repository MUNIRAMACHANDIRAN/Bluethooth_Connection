import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

def select_files():
    files = filedialog.askopenfilenames(filetypes=[("MP3 files", "*.mp3")])
    if files:
        mp3_files.clear()
        mp3_files.extend(files)
        file_listbox.delete(0, tk.END)
        for f in mp3_files:
            file_listbox.insert(tk.END, os.path.basename(f))

def select_output_directory():
    directory = filedialog.askdirectory()
    if directory:
        output_dir.set(directory)

def convert_files():
    if not mp3_files:
        messagebox.showwarning("No Files", "Please select MP3 files to convert.")
        return
    if not output_dir.get():
        messagebox.showwarning("No Output Directory", "Please select an output directory.")
        return

    progress_bar["maximum"] = len(mp3_files)
    progress_bar["value"] = 0
    status_label.config(text="Starting conversion...")

    for i, mp3_file in enumerate(mp3_files):
        try:
            output_file = os.path.join(
                output_dir.get(),
                os.path.splitext(os.path.basename(mp3_file))[0] + ".dts"
            )
            # Use ffmpeg DTS encoder (dca)
            subprocess.run(
                ["ffmpeg", "-y", "-i", mp3_file, "-c:a", "dca", output_file],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT
            )
            status_label.config(text=f"Converted: {os.path.basename(mp3_file)}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Conversion Error", f"Failed to convert {mp3_file}\n{e}")
        progress_bar["value"] = i + 1
        root.update_idletasks()

    status_label.config(text="Conversion completed.")

root = tk.Tk()
root.title("MP3 to DTS Batch Converter")

mp3_files = []
output_dir = tk.StringVar()

file_frame = ttk.LabelFrame(root, text="Select MP3 Files")
file_frame.pack(fill="x", padx=10, pady=5)

ttk.Button(file_frame, text="Browse Files", command=select_files).pack(side="left", padx=5, pady=5)
file_listbox = tk.Listbox(file_frame, height=6)
file_listbox.pack(fill="both", expand=True, padx=5, pady=5)

output_frame = ttk.LabelFrame(root, text="Select Output Directory")
output_frame.pack(fill="x", padx=10, pady=5)

ttk.Entry(output_frame, textvariable=output_dir).pack(side="left", fill="x", expand=True, padx=5, pady=5)
ttk.Button(output_frame, text="Browse Folder", command=select_output_directory).pack(side="left", padx=5, pady=5)

ttk.Button(root, text="Convert to DTS", command=convert_files).pack(pady=10)
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=5)
status_label = ttk.Label(root, text="Waiting for files...")
status_label.pack(pady=5)

root.mainloop()
