import numpy as np
from sklearn.svm import OneClassSVM
import joblib

# Normal traffic training data
# Features: [total_logs, unique_src_ips, unique_ports]
# Example data (make sure to use realistic training data for your scenario)
X_train = np.array([
    [2, 1, 2],   # e.g., 2 logs, 1 unique IP, 2 unique ports
    [1, 1, 1],
    [1, 1, 1],
    [2, 1, 2],
    [1, 1, 1],
    [1, 1, 1],
])

# Train OneClassSVM with 3 features
model = OneClassSVM(kernel="rbf", gamma=0.1, nu=0.1)
model.fit(X_train)

# Save the trained model
joblib.dump(model, "svm_model.pkl")
print("SVM model trained with 3 features and saved as svm_model.pkl")
