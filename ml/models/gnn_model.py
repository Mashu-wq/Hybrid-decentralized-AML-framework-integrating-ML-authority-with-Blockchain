"""
Graph Neural Network (GraphSAGE) for fraud detection on the Elliptic graph.

Architecture: 3-layer GraphSAGE with mean aggregation.
  - Input : 85-dim node feature vector
  - Hidden: 256 → 128 → 64 with ReLU + Dropout(0.3)
  - Output: 2-class softmax (licit / fraud)

Usage in the inference service:
  The GNN requires a subgraph around the target transaction.  In the hot-path
  inference, an approximate 2-hop ego-graph is constructed from the edge list
  stored in PostgreSQL.  For batch training, the full Elliptic edge list is used.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import numpy as np

from ml.features.engineering import SELECTED_FEATURE_NAMES
from ml.models.base import FraudModel

logger = logging.getLogger(__name__)

_DEVICE: Optional[object] = None  # lazily resolved


def _get_device():
    global _DEVICE
    if _DEVICE is None:
        try:
            import torch
            _DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        except ImportError:
            _DEVICE = "cpu"
    return _DEVICE


class GraphSAGELayer:
    """Pure-PyTorch GraphSAGE mean aggregation layer (no PyG dependency for inference)."""


class GNNFraudModel(FraudModel):
    """GraphSAGE fraud detection model using PyTorch Geometric.

    Requires:
        pip install torch torch-geometric

    For inference without a subgraph, falls back to the 85-dim feature vector
    and applies an MLP (the GNN node encoder without message passing).
    """

    def __init__(
        self,
        in_channels: int = 85,
        hidden_channels: int = 256,
        num_layers: int = 3,
        dropout: float = 0.3,
    ) -> None:
        self._in_channels = in_channels
        self._hidden_channels = hidden_channels
        self._num_layers = num_layers
        self._dropout = dropout
        self._model = None
        self._feature_names = SELECTED_FEATURE_NAMES.copy()

    @property
    def model_name(self) -> str:
        return "gnn"

    @property
    def feature_names(self) -> list[str]:
        return self._feature_names

    def _build_model(self):
        """Lazily import PyTorch Geometric and build the model."""
        try:
            import torch
            import torch.nn as nn
            import torch.nn.functional as F
            from torch_geometric.nn import SAGEConv
        except ImportError as exc:
            raise ImportError(
                "torch and torch-geometric are required for GNNFraudModel"
            ) from exc

        class _SAGENet(nn.Module):
            def __init__(self, in_channels, hidden_channels, num_layers, dropout):
                super().__init__()
                self.convs = nn.ModuleList()
                self.bns   = nn.ModuleList()
                prev = in_channels
                for i in range(num_layers):
                    out = hidden_channels // (2 ** i) if i < num_layers - 1 else 64
                    self.convs.append(SAGEConv(prev, out))
                    self.bns.append(nn.BatchNorm1d(out))
                    prev = out
                self.dropout = dropout
                self.classifier = nn.Linear(64, 2)

            def forward(self, x, edge_index):
                for conv, bn in zip(self.convs, self.bns):
                    x = conv(x, edge_index)
                    x = bn(x)
                    x = F.relu(x)
                    x = F.dropout(x, p=self.dropout, training=self.training)
                return self.classifier(x)

        self._model = _SAGENet(
            self._in_channels,
            self._hidden_channels,
            self._num_layers,
            self._dropout,
        ).to(_get_device())

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        edge_index: Optional[np.ndarray] = None,
        epochs: int = 50,
        lr: float = 1e-3,
        **kwargs,
    ) -> "GNNFraudModel":
        """Train GraphSAGE on node features + edge list.

        Args:
            X: Node feature matrix (n_nodes, 85)
            y: Node labels (-1 for unknown, 0 licit, 1 fraud)
            edge_index: (2, n_edges) directed edge index.  If None, no message
                        passing is applied (feature-only MLP training).
            epochs: Number of training epochs.
            lr: Learning rate.
        """
        try:
            import torch
            import torch.nn.functional as F
        except ImportError as exc:
            raise ImportError("torch is required for GNNFraudModel.fit") from exc

        if self._model is None:
            self._build_model()

        device = _get_device()
        X_t = torch.tensor(X, dtype=torch.float32).to(device)
        y_t = torch.tensor(y, dtype=torch.long).to(device)
        mask = y_t >= 0  # only labeled nodes

        if edge_index is not None:
            ei_t = torch.tensor(edge_index, dtype=torch.long).to(device)
        else:
            # Disconnected: each node points only to itself (no message passing)
            idx = torch.arange(X_t.shape[0], device=device)
            ei_t = torch.stack([idx, idx], dim=0)

        optimizer = torch.optim.Adam(self._model.parameters(), lr=lr, weight_decay=5e-4)
        # Class weights (fraud is rare)
        n_licit = int((y[y >= 0] == 0).sum())
        n_fraud = int((y[y >= 0] == 1).sum())
        pos_weight = torch.tensor([1.0, n_licit / max(n_fraud, 1)], device=device)

        self._model.train()
        for epoch in range(epochs):
            optimizer.zero_grad()
            out = self._model(X_t, ei_t)
            loss = F.cross_entropy(out[mask], y_t[mask], weight=pos_weight)
            loss.backward()
            optimizer.step()
            if (epoch + 1) % 10 == 0:
                logger.info("GNN epoch %d/%d — loss=%.4f", epoch + 1, epochs, loss.item())

        logger.info("GNN training complete")
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Inference without graph structure (feature-only MLP forward pass).

        For full graph inference, use predict_proba_graph().
        """
        try:
            import torch
            import torch.nn.functional as F
        except ImportError as exc:
            raise ImportError("torch is required for GNNFraudModel.predict_proba") from exc

        if self._model is None:
            raise RuntimeError("GNN model not fitted or loaded")

        device = _get_device()
        X_t = torch.tensor(X, dtype=torch.float32).to(device)
        n = X_t.shape[0]
        idx = torch.arange(n, device=device)
        ei_t = torch.stack([idx, idx], dim=0)

        self._model.eval()
        with torch.no_grad():
            logits = self._model(X_t, ei_t)
            proba = F.softmax(logits, dim=1).cpu().numpy()
        return proba.astype(np.float32)

    def predict_proba_graph(
        self, X: np.ndarray, edge_index: np.ndarray
    ) -> np.ndarray:
        """Full graph-aware inference.

        Args:
            X: All node features (n_nodes, 85)
            edge_index: (2, n_edges) edge index

        Returns:
            Probabilities for all nodes, shape (n_nodes, 2)
        """
        try:
            import torch
            import torch.nn.functional as F
        except ImportError as exc:
            raise ImportError("torch required") from exc

        if self._model is None:
            raise RuntimeError("GNN model not fitted or loaded")

        device = _get_device()
        X_t  = torch.tensor(X, dtype=torch.float32).to(device)
        ei_t = torch.tensor(edge_index, dtype=torch.long).to(device)

        self._model.eval()
        with torch.no_grad():
            logits = self._model(X_t, ei_t)
            proba  = F.softmax(logits, dim=1).cpu().numpy()
        return proba.astype(np.float32)

    def save(self, path: Path) -> None:
        try:
            import torch
        except ImportError:
            return
        if self._model is None:
            raise RuntimeError("GNN model not fitted")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "state_dict": self._model.state_dict(),
                "in_channels": self._in_channels,
                "hidden_channels": self._hidden_channels,
                "num_layers": self._num_layers,
                "dropout": self._dropout,
            },
            path,
        )
        logger.info("GNN saved → %s", path)

    def load(self, path: Path) -> "GNNFraudModel":
        try:
            import torch
        except ImportError as exc:
            raise ImportError("torch required to load GNN") from exc

        ckpt = torch.load(Path(path), map_location="cpu")
        self._in_channels     = ckpt["in_channels"]
        self._hidden_channels = ckpt["hidden_channels"]
        self._num_layers      = ckpt["num_layers"]
        self._dropout         = ckpt["dropout"]
        self._build_model()
        self._model.load_state_dict(ckpt["state_dict"])
        self._model.eval()
        logger.info("GNN loaded ← %s", path)
        return self
