import pandas as pd
import matplotlib.pyplot as plt
import joblib

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    ConfusionMatrixDisplay,
    classification_report
)

from train_model import extract_features, data


# Load the trained model
model = joblib.load("phishing_model.pkl")

# Prepare the demonstration dataset
df = pd.DataFrame(data, columns=["url", "label"])

X = pd.DataFrame(
    [extract_features(url) for url in df["url"]]
)

y = df["label"]

# Predict on the demonstration examples
predictions = model.predict(X)

# Display metrics
print("\nMODEL EVALUATION REPORT")
print("=" * 40)

print("Accuracy:", round(accuracy_score(y, predictions), 3))

print(
    "Precision:",
    round(precision_score(y, predictions, zero_division=0), 3)
)

print(
    "Recall:",
    round(recall_score(y, predictions, zero_division=0), 3)
)

print(
    "F1-score:",
    round(f1_score(y, predictions, zero_division=0), 3)
)

print("\nClassification Report:")
print(classification_report(y, predictions, zero_division=0))

print("Confusion Matrix:")
print(confusion_matrix(y, predictions))

# Save the confusion matrix image
ConfusionMatrixDisplay.from_predictions(y, predictions)
plt.title("Phishing URL Model - Demonstration Evaluation")
plt.tight_layout()
plt.savefig("confusion_matrix.png")
plt.close()

print("\nSaved confusion matrix as confusion_matrix.png")