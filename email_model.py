import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

import joblib


# Load cleaned dataset
df = pd.read_csv("Phislens/dataset_email/Balanced_Dataset.csv")

# Features and target
X = df["body"]
y = df["label"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training Emails:", len(X_train))
print("Testing Emails:", len(X_test))


# Create NLP Pipeline
email_model = Pipeline([
    ("tfidf", TfidfVectorizer(
        max_features=50000,
        stop_words="english"
    )),

    ("classifier", LogisticRegression(
        max_iter=1000
    ))
])


# Train model
email_model.fit(X_train, y_train)

print("\nModel Training Completed!")


# Test model
y_pred = email_model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))


# Save model
joblib.dump(email_model, "email_model.pkl")

print("\nEmail Model Saved Successfully!")