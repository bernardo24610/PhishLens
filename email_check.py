import pandas as pd

dataset_path = "Phislens/dataset_email/Balanced_Dataset.csv"

df = pd.read_csv(dataset_path)

# Remove emails with missing body
df = df.dropna(subset=["body"])

# Convert labels from float to integer
df["label"] = df["label"].astype(int)

print("Dataset Shape After Cleaning:", df.shape)

print("\nLabels Distribution:")
print(df["label"].value_counts())

# Save cleaned dataset
df.to_csv("Phislens/dataset_email/Balanced_Dataset.csv", index=False)

print("\nCleaned Dataset Saved Successfully!")