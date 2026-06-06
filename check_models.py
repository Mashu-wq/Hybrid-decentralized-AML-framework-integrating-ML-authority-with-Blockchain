import joblib, json, numpy as np

rf  = joblib.load("ml/artifacts/random_forest_model.pkl")
xgb = joblib.load("ml/artifacts/xgboost_model.pkl")
lgb = joblib.load("ml/artifacts/lightgbm_model.pkl")

with open("ml/artifacts/ensemble.json") as f:
    meta = json.load(f)

X = np.random.rand(1, 85).astype("float32")

print(f"RF  — features: {rf.n_features_in_}  | P(fraud): {rf.predict_proba(X)[0][1]:.4f}")
print(f"XGB — features: {xgb.n_features_in_} | P(fraud): {xgb.predict_proba(X)[0][1]:.4f}")
print(f"LGB — features: {lgb.n_features_in_} | P(fraud): {lgb.predict_proba(X)[0][1]:.4f}")
print(f"Ensemble weights: {meta['weights']}")
print("All models OK!")
