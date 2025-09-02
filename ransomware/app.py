from tkinter import *
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import f1_score, accuracy_score,recall_score, precision_score
from scipy.stats import randint, uniform
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC as SupportVectorClassifier

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier



global filename
global df, X_train, X_test, y_train, y_test
global lgb_model

main = tk.Tk()
main.title("Ransomware Attack Detection")
main.geometry("1600x1500")

import tkinter
from tkinter import PhotoImage
image_path=PhotoImage(file="hacker_glitch-wallpaper-1600x900.png")

bg_image=tkinter.Label(main,image=image_path)
bg_image.place(relheight=1,relwidth=1)
df = None
X_train = X_test = y_train = y_test = None
results = []  # To store model results for plotting
# Add a custom gradient background
def set_gradient_background(widget):
    gradient = PhotoImage(width=1600, height=150)
    for i in range(150):
        r = int(255 - (i * 255 / 150))
        g = int(105 - (i * 105 / 150))
        b = int(180 - (i * 180 / 150))
        color = f"#{r:02x}{g:02x}{b:02x}"
        gradient.put(color, to=(0, i, 1600, i+1))
    widget.create_image(0, 0, anchor=NW, image=gradient)
    widget.gradient = gradient  # Prevent garbage collection

# Create a canvas for the title background
title_canvas = Canvas(main, height=150, width=1600)
title_canvas.place(x=0, y=0)
set_gradient_background(title_canvas)

# Configure the title label with new font style and colors
title_font = ('Helvetica', 24, 'bold italic')
title = tk.Label(main, text='Ransomware Attack Detection', font=title_font, bg='#ff69b4', fg='white')
title.place(relx=0.5, rely=0.1, anchor=CENTER)

font1 = ('times', 14, 'bold')
text = tk.Text(main, height=16, width=80, bg=main.cget("bg"), highlightthickness=0)
scroll = tk.Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=400, y=160)
text.config(font=font1)


style = ttk.Style()
style.configure("TButton",
                font=('times', 13, 'bold'),
                background='blue',
                foreground='red',
                padding=10,
                focuscolor='none')
style.map("TButton",
          foreground=[('active', '#000000')],
          background=[('active', '#81C784')],
          relief=[('pressed', 'groove')],
          highlightcolor=[('focus', '#ffffff')],
          highlightbackground=[('focus', '#ffffff')])

def on_enter(e):
    e.widget['background'] = '#81C784'
    e.widget['foreground'] = '#000000'

def on_leave(e):
    e.widget['background'] = '#4CAF50'
    e.widget['foreground'] = '#ffffff'

def upload():
    global filename, df
    filename = filedialog.askopenfilename(initialdir="dataset")
    pathlabel.config(text=filename)
    df = pd.read_csv(filename)

    # Drop specified columns
    df.drop(columns=["FileName", "md5Hash"], inplace=True)

    text.delete('1.0', END)
    text.insert(END, 'Dataset loaded\n')
    text.insert(END, "Dataset Size(Number of Rows): " + str(len(df)) + "\n")
    text.insert(END, "Dataset Size(Number of Columns): " + str(len(df.columns)) + "\n")


def split_data():
    global X_train, X_test, y_train, y_test
    X = df.drop("Benign", axis=1)
    y = df["Benign"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    text.delete('1.0', END)
    text.insert(END, "Data Split Completed\n")
    text.insert(END, f"Training Data Shape: {X_train.shape}\n")
    text.insert(END, f"Testing Data Shape: {X_test.shape}\n")

def run_random_forest():
    global results, RF
    if X_train is not None:
        RF = RandomForestClassifier()
        RF.fit(X_train, y_train)
        y_pred = RF.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, digits=4)

        results.append({"Model": "Random Forest", "Accuracy": acc})

        text.delete('1.0', END)
        text.insert(END, "===== Random Forest =====\n")
        text.insert(END, f"Accuracy: {round(acc, 4)}\n")
        text.insert(END, "Classification Report:\n")
        text.insert(END, report)
    else:
        text.delete('1.0', END)
        text.insert(END, "Please split the data first.\n")


# Function 4: Decision Tree
def run_decision_tree():
    global results
    if X_train is not None:
        model = DecisionTreeClassifier()
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, digits=4)

        results.append({"Model": "Decision Tree", "Accuracy": acc})

        text.delete('1.0', END)
        text.insert(END, "===== Decision Tree =====\n")
        text.insert(END, f"Accuracy: {round(acc, 4)}\n")
        text.insert(END, "Classification Report:\n")
        text.insert(END, report)
    else:
        text.delete('1.0', END)
        text.insert(END, "Please split the data first.\n")

# Function 5: XGBoost
def run_xgboost():
    global results
    if X_train is not None:
        model = XGBClassifier(use_label_encoder=False, eval_metric="logloss")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, digits=4)

        results.append({"Model": "XGBoost", "Accuracy": acc})

        text.delete('1.0', END)
        text.insert(END, "===== XGBoost =====\n")
        text.insert(END, f"Accuracy: {round(acc, 4)}\n")
        text.insert(END, "Classification Report:\n")
        text.insert(END, report)
    else:
        text.delete('1.0', END)
        text.insert(END, "Please split the data first.\n")

# Function 6: Plot Accuracy
def plot_accuracy():
    if len(results) > 0:
        result_df = pd.DataFrame(results)

        plt.figure(figsize=(8, 4))
        ax = sns.barplot(data=result_df, x="Model", y="Accuracy", palette=sns.color_palette("Purples_d"))

        plt.title("Accuracy Score", fontsize=14)
        plt.ylabel("Accuracy Score", fontsize=12)
        plt.xlabel("Model", fontsize=12)
        plt.xticks(fontsize=10)
        plt.yticks(fontsize=10)
        plt.grid(True, axis='y', linestyle='--', alpha=0.5)

        for p in ax.patches:
            ax.annotate(f"{p.get_height():.4f}", 
                        (p.get_x() + p.get_width() / 2., p.get_height()), 
                        ha='center', va='bottom', fontsize=10, color='#4B0082')

        plt.tight_layout()
        plt.show()
    else:
        text.delete('1.0', END)
        text.insert(END, "Please run some models first.\n")

def predict():
    filename = filedialog.askopenfilename(
        initialdir="dataset", 
        title="Select CSV File for Prediction", 
        filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
    )
    
    if filename:
        data = pd.read_csv(filename)
        
        # Drop the same columns as in training
        if "FileName" in data.columns and "md5Hash" in data.columns:
            data.drop(columns=["FileName", "md5Hash"], inplace=True)
        
        # Ensure the columns match exactly with X_train
        data = data[X_train.columns]
        
        # Take only the first 13 rows
        data = data.head(13)
        
        predictions = RF.predict(data)
        
        text.delete('1.0', END)
        text.insert(END, "Predictions for First 13 Rows:\n")
        for idx, prediction in enumerate(predictions, start=1):
            if prediction == 1:
                text.insert(END, f'Row {idx}: The Predicted Output is: Ransomware Attack Detected\n')
            else:
                text.insert(END, f'Row {idx}: The Predicted Output is: Ransomware Attack Not Detected\n')
    else:
        messagebox.showinfo("Info", "No file selected for prediction.")





uploadButton = ttk.Button(main, text="Upload Dataset", command=upload, width=16)
uploadButton.place(x=50, y=600)
uploadButton.bind("<Enter>", on_enter)
uploadButton.bind("<Leave>", on_leave)

uploadButton = ttk.Label(main, text="File: ")
uploadButton.place(x=350, y=550)
uploadButton.config(font=font1)

pathlabel = tk.Label(main)
pathlabel.config(bg='DarkOrange1', fg='white')
pathlabel.config(font=font1)
pathlabel.place(x=400, y=550)

button2 = ttk.Button(main, text="Split Data", command=split_data, width=17)
button2.place(x=250, y=600)
button2.bind("<Enter>", on_enter)
button2.bind("<Leave>", on_leave)


button3 = ttk.Button(main, text="Random Forest", command=run_random_forest, width=17)
button3.place(x=450, y=600)

button4 = ttk.Button(main, text="Decision Tree", command=run_decision_tree, width=17)
button4.place(x=650, y=600)

button5 = ttk.Button(main, text="XGBoost", command=run_xgboost, width=17)
button5.place(x=850, y=600)


button6 = ttk.Button(main, text="Plot Accuracy", command=plot_accuracy, style="TButton", width=17)
button6.place(x=1250, y=600)

button7 = ttk.Button(main, text="Predict", command=predict, width=17)
button7.place(x=1050, y=600)



#main.config(bg='#32d1a7')
main.mainloop()
