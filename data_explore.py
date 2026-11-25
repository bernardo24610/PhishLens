import pandas as pd
from scipy.io import arff

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.model_selection import cross_val_score, StratifiedKFold

import joblib


# Load Dataset
data, metadata = arff.loadarff("notebook/Training Dataset.arff")

df = pd.DataFrame(data)
df = df.astype(int)

print(df.iloc[0].apply(type))


# Split Features and Target
X = df.drop("Result", axis=1)
Y = df["Result"]


# Train Test Split
X_train, X_test, Y_train, Y_test = train_test_split(
    X, Y, test_size=0.2, random_state=40
)


# Logistic Regression
model = LogisticRegression()

model.fit(X_train, Y_train)

Y_predict = model.predict(X_test)

print(Y_predict)

accuracy = accuracy_score(Y_test, Y_predict)
print(accuracy)

print(confusion_matrix(Y_test, Y_predict))

print(classification_report(Y_test, Y_predict))


# Error Analysis
errors = X_test[(Y_test == -1) & (Y_predict == 1)]
print(errors)

print(errors["URL_Length"].value_counts())

correct = X_test[(Y_test == -1) & (Y_predict == -1)]

print(correct["URL_Length"].value_counts())

print(errors["having_IP_Address"].value_counts())
print(correct["having_IP_Address"].value_counts())

print(errors["SSLfinal_State"].value_counts())
print(correct["SSLfinal_State"].value_counts())


# Feature Analysis
print(df.groupby("SSLfinal_State")["Result"].value_counts(normalize=True) * 100)

print(classification_report(
    Y_test, Y_predict,
    labels=[-1, 1]
))

feature_importance = pd.DataFrame({
    "Feature": X.columns,
    "Coefficient": model.coef_[0],
    "Absolute Importance": abs(model.coef_[0])
})

feature_importance = feature_importance.sort_values(
    by="Absolute Importance",
    ascending=False
)

print(feature_importance)

print(df.groupby("Result")["URL_of_Anchor"].value_counts(normalize=True) * 100)

print(model.classes_)


# Standard Scaling
scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(X_train_scaled.shape)
print(X_test_scaled.shape)

model_scaled = LogisticRegression(max_iter=1000)

model_scaled.fit(X_train_scaled, Y_train)

Y_predict_scaled = model_scaled.predict(X_test_scaled)

print("Accuracy:", accuracy_score(Y_test, Y_predict_scaled))

print(confusion_matrix(Y_test, Y_predict_scaled))

print(classification_report(Y_test, Y_predict_scaled))


# Random Forest
rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

rf_model.fit(X_train, Y_train)

rf_predict = rf_model.predict(X_test)

print("Accuracy:", accuracy_score(Y_test, rf_predict))

print(confusion_matrix(Y_test, rf_predict))

print(classification_report(Y_test, rf_predict))


# Random Forest Feature Importance
rf_importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": rf_model.feature_importances_
})

rf_importance = rf_importance.sort_values(
    by="Importance",
    ascending=False
)

print(rf_importance)


# Permutation Importance
perm = permutation_importance(
    rf_model,
    X_test,
    Y_test,
    n_repeats=5,
    random_state=42,
    scoring="accuracy"
)

perm_importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": perm.importances_mean
})

perm_importance = perm_importance.sort_values(
    by="Importance",
    ascending=False
)

print(perm_importance)


# Cross Validation
cv = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)

cv_scores = cross_val_score(
    rf_model,
    X,
    Y,
    cv=cv,
    scoring="accuracy"
)

print("Scores:", cv_scores)
print("Mean Accuracy:", cv_scores.mean())
print("Standard Deviation:", cv_scores.std())


# Save Model
joblib.dump(rf_model, "phishing_model.pkl")


# Load Model
loaded_model = joblib.load("phishing_model.pkl")

test_prediction = loaded_model.predict(X_test)

print(accuracy_score(Y_test, test_prediction))
print(X.columns.tolist())
print(X_test.iloc[0].to_dict())
print("Actual Result:", Y_test.iloc[0])
print(df["URL_Length"].value_counts().sort_index())
print(df.groupby("URL_Length")["Result"].value_counts(normalize=True) * 100)

