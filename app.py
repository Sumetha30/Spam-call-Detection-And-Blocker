import tkinter as tk
from tkinter import messagebox, ttk
import csv
import networkx as nx
import matplotlib.pyplot as plt
import heapq

# CSV Operations
def load_spam_csv():
    try:
        with open("spam_numbers.csv", "r") as file:
            reader = csv.reader(file)
            return set(row[0] for row in reader)
    except FileNotFoundError:
        return set()

def update_spam_csv(number):
    with open("spam_numbers.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([number])

def load_user_blocked_csv(user_number):
    try:
        with open(f"blocked_{user_number}.csv", "r") as file:
            reader = csv.reader(file)
            return [row[0] for row in reader]
    except FileNotFoundError:
        return []

def update_user_blocked_csv(user_number, number):
    with open(f"blocked_{user_number}.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([number])

def remove_user_blocked_csv(user_number, number):
    blocked_numbers = load_user_blocked_csv(user_number)
    blocked_numbers = [num for num in blocked_numbers if num != number]
    with open(f"blocked_{user_number}.csv", "w", newline="") as file:
        writer = csv.writer(file)
        for num in blocked_numbers:
            writer.writerow([num])

def multistage_graph_evaluation(stages):
    total_score = 0
    reasons = []
    for stage in stages:
        if stage:
            score, reason = stage[0]
            total_score += score
            reasons.append(reason)
    return total_score, reasons

class AVLNode:
    def __init__(self, number):
        self.number = number
        self.frequency = 1
        self.left = None
        self.right = None

class AVLTree:
    def __init__(self):
        self.root = None

    def insert_or_increment(self, root, number):
        if not root:
            return AVLNode(number)
        if number == root.number:
            root.frequency += 1
        elif number < root.number:
            root.left = self.insert_or_increment(root.left, number)
        else:
            root.right = self.insert_or_increment(root.right, number)
        return root

    def search(self, root, number):
        if not root:
            return None
        if number == root.number:
            return root
        elif number < root.number:
            return self.search(root.left, number)
        else:
            return self.search(root.right, number)

class SpamDetectorApp:
    def __init__(self, master):
        self.master = master
        master.title("📞 Real-Time Spam Call Detector")
        master.geometry("520x650")

        # Inputs
        tk.Label(master, text="Enter Your Phone Number:", font=("Arial", 12)).pack(pady=5)
        self.user_phone_entry = tk.Entry(master, font=("Arial", 14))
        self.user_phone_entry.pack(pady=5)

        tk.Label(master, text="Enter Phone Number to Check:", font=("Arial", 12)).pack(pady=5)
        self.phone_entry = tk.Entry(master, font=("Arial", 14))
        self.phone_entry.pack(pady=5)

        tk.Label(master, text="Enter Suspicious Word (if any):", font=("Arial", 12)).pack(pady=5)
        self.word_entry = tk.Entry(master, font=("Arial", 14))
        self.word_entry.pack(pady=5)

        self.button_frame = tk.Frame(master)
        self.button_frame.pack(pady=15)

        # Buttons
        tk.Button(self.button_frame, text="Check for Spam", command=self.check_spam, font=("Arial", 12)).grid(row=0, column=0, padx=10)
        tk.Button(self.button_frame, text="Report Scam", command=self.report_scam, font=("Arial", 12)).grid(row=0, column=1, padx=10)
        tk.Button(self.button_frame, text="Block Number", command=self.block_number, font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=5)
        tk.Button(self.button_frame, text="Unblock Number", command=self.unblock_number, font=("Arial", 12)).grid(row=1, column=1, padx=10, pady=5)
        tk.Button(self.button_frame, text="View Blocked", command=self.view_blocked, font=("Arial", 12)).grid(row=2, column=0, columnspan=2, pady=5)
        tk.Button(self.button_frame, text="Show Graph", command=self.show_graph, font=("Arial", 12)).grid(row=3, column=0, columnspan=2, pady=5)
        tk.Button(self.button_frame, text="Show Top Scam Numbers", command=self.show_top_spam, font=("Arial", 12)).grid(row=4, column=0, columnspan=2, pady=5)

        # Output
        self.status_icon = tk.Label(master, text="", font=("Arial", 40))
        self.status_icon.pack(pady=10)

        self.result_label = tk.Label(master, text="", font=("Arial", 12), fg="blue", wraplength=480, justify="left")
        self.result_label.pack(pady=10)

        self.progress = ttk.Progressbar(master, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=5)

        self.wordcloud_label = tk.Label(master, text="Suspicious Words: win, prize, free, lottery, urgent, call now", font=("Arial", 10), fg="darkred")
        self.wordcloud_label.pack(pady=5)

        # Data
        self.spam_numbers = load_spam_csv()
        self.report_counter = {}
        self.suspicious_words = {"win", "prize", "free", "lottery", "urgent", "call now"}

        self.avl = AVLTree()
        self.root_node = None
        self.graph = {"1234567890": ["111", "222"]}
        self.spam_heap = [(10, "1234567890")]
        self.spam_scores = {"1234567890": 3}

    def check_spam(self):
        num = self.phone_entry.get().strip().replace('-', '').replace(' ', '')
        word = self.word_entry.get().strip().lower()

        if not num:
            messagebox.showerror("Input Error", "Please enter the phone number.")
            return

        self.status_icon.config(text="")
        self.progress['value'] = 0
        self.result_label.config(text="")

        if num in self.spam_numbers:
            self.progress['value'] = 100
            self.status_icon.config(text="⚠", fg="red")
            self.result_label.config(text=f"{num} is already listed as spam.")
            return

        node = self.avl.search(self.root_node, num)
        stage1 = [(1, f"Suspicious word '{word}' detected")] if word and word in self.suspicious_words else []
        stage2 = [(node.frequency / 2, f"Reported {node.frequency} times")] if node and node.frequency >= 3 else []
        stage3 = [(len(self.graph.get(num, [])) / 2, f"Called {len(self.graph.get(num, []))} numbers")] if num in self.graph and len(self.graph[num]) >= 2 else []
        stage4 = [(2, "Listed in top spam reports")] if num in [n for _, n in self.spam_heap] else []
        stage5 = [(1, "Found in spam score table")] if num in self.spam_scores else []
        stage6 = [(2, "Reported in real-world spam dataset")] if num in self.spam_numbers else []

        total_score, reasons = multistage_graph_evaluation([stage1, stage2, stage3, stage4, stage5, stage6])
        self.progress['value'] = min(total_score * 20, 100)

        if total_score >= 3:
            self.status_icon.config(text="⚠", fg="red")
            self.result_label.config(text=f"{num} is likely spam!\n\nReasons:\n" + "\n".join(reasons))
        else:
            self.status_icon.config(text="✔", fg="green")
            self.result_label.config(text=f"{num} appears to be safe.")

    def report_scam(self):
        num = self.phone_entry.get().strip().replace('-', '').replace(' ', '')
        if not num:
            messagebox.showerror("Input Error", "Please enter the phone number to report.")
            return

        self.root_node = self.avl.insert_or_increment(self.root_node, num)
        node = self.avl.search(self.root_node, num)
        self.report_counter[num] = self.report_counter.get(num, 0) + 1

        if node and node.frequency >= 3 and num not in self.spam_numbers:
            self.spam_numbers.add(num)
            update_spam_csv(num)
            messagebox.showinfo("Spam Reported", f"{num} has been reported more than 3 times and added to the spam list.")
        else:
            messagebox.showinfo("Report Received", f"{num} has been reported. It will be reviewed.")

    def block_number(self):
        num = self.phone_entry.get().strip().replace('-', '').replace(' ', '')
        user_number = self.user_phone_entry.get().strip().replace('-', '').replace(' ', '')

        if not num or not user_number:
            messagebox.showerror("Input Error", "Please enter both your phone number and the number to block.")
            return

        blocked_numbers = load_user_blocked_csv(user_number)
        if num in blocked_numbers:
            messagebox.showinfo("Already Blocked", f"{num} is already blocked.")
            return

        update_user_blocked_csv(user_number, num)
        messagebox.showinfo("Blocked", f"{num} has been blocked.")

    def unblock_number(self):
        num = self.phone_entry.get().strip().replace('-', '').replace(' ', '')
        user_number = self.user_phone_entry.get().strip().replace('-', '').replace(' ', '')

        if not num or not user_number:
            messagebox.showerror("Input Error", "Please enter both your phone number and the number to unblock.")
            return

        remove_user_blocked_csv(user_number, num)
        messagebox.showinfo("Unblocked", f"{num} has been unblocked.")

    def view_blocked(self):
        user_number = self.user_phone_entry.get().strip().replace('-', '').replace(' ', '')
        if not user_number:
            messagebox.showerror("Input Error", "Please enter your phone number.")
            return

        blocked_numbers = load_user_blocked_csv(user_number)
        if blocked_numbers:
            blocked_list = "\n".join(blocked_numbers)
            messagebox.showinfo("Blocked Numbers", f"Your blocked numbers:\n{blocked_list}")
        else:
            messagebox.showinfo("No Blocked Numbers", "You have not blocked any numbers yet.")

    def show_top_spam(self):
        if not self.report_counter:
            messagebox.showinfo("Top Scams", "No scam reports yet.")
            return

        heap = [(-count, num) for num, count in self.report_counter.items()]
        top_spams = heapq.nsmallest(5, heap)
        report_text = "\n".join([f"{num}: {-count} reports" for count, num in top_spams])
        messagebox.showinfo("Top Scam Numbers", f"Top reported scam numbers:\n\n{report_text}")

    def show_graph(self):
        user_number = self.user_phone_entry.get().strip().replace('-', '').replace(' ', '')
        if not user_number:
            messagebox.showerror("Input Error", "Please enter your phone number to display the graph.")
            return

        blocked_numbers = load_user_blocked_csv(user_number)
        G = nx.Graph()
        G.add_node(user_number)
        for num in blocked_numbers:
            G.add_node(num)
            G.add_edge(user_number, num)

        pos = nx.spring_layout(G)
        plt.figure(figsize=(8, 6))
        nx.draw(G, pos, with_labels=True, node_color="lightblue", node_size=2000, font_size=10, font_weight='bold')
        plt.title(f"Blocked Numbers for {user_number}")
        plt.show()

# Run App
if __name__ == "__main__":
    root = tk.Tk()
    app = SpamDetectorApp(root)
    root.mainloop()