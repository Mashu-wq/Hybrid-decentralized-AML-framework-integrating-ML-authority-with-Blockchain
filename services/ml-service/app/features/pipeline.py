"""
Feature pipeline — converts proto TransactionFeatures → numpy array.

This is the single entry point for all feature transformation in inference.
It delegates to ml.features.engineering for the actual mapping logic.
"""
from __future__ import annotations

import numpy as np

from ml.features.engineering import (
    NUM_MODEL_FEATURES,
    SELECTED_FEATURE_NAMES,
    proto_features_to_array,
)


class FeaturePipeline:
    """Stateless feature pipeline for inference.

    Usage:
        pipeline = FeaturePipeline()
        X = pipeline.transform(proto_features)       # shape (1, 85)
        X_batch = pipeline.transform_batch(features_list)  # shape (n, 85)
    """

    @property
    def feature_names(self) -> list[str]:
        return SELECTED_FEATURE_NAMES

    @property
    def num_features(self) -> int:
        return NUM_MODEL_FEATURES

    def transform(self, features) -> np.ndarray:
        """Convert a single proto TransactionFeatures message to (1, 85) array.

        Args:
            features: proto TransactionFeatures instance

        Returns:
            numpy float32 array of shape (1, NUM_MODEL_FEATURES)
        """
        return proto_features_to_array(features)

    def transform_batch(self, features_list) -> np.ndarray:
        """Convert a list of proto TransactionFeatures to (n, 85) array.

        Args:
            features_list: iterable of proto TransactionFeatures

        Returns:
            numpy float32 array of shape (n, NUM_MODEL_FEATURES)
        """
        arrays = [proto_features_to_array(f) for f in features_list]
        if not arrays:
            return np.empty((0, NUM_MODEL_FEATURES), dtype=np.float32)
        return np.vstack(arrays).astype(np.float32)
