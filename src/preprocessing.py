"""Cleaning and feature-selection steps shared by the notebook and the Streamlit app.

The notebook must import these classes from here (``from src.preprocessing import ...``)
instead of defining them in a cell. A pipeline pickled with classes defined in a notebook
cell refers to ``__main__.<ClassName>`` and cannot be loaded by any other program.
"""
import polars as pl
import polars.selectors as cs
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder
from sklearn.utils.validation import check_is_fitted

IDENTIFIER_COLUMNS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp"]


class IdentifierColumnsRemover(TransformerMixin, BaseEstimator):
    def __init__(self, features_to_drop: list[str] = IDENTIFIER_COLUMNS) -> None:
        self.features_to_drop = features_to_drop

    def fit(self, X: pl.DataFrame, y=None):
        self.n_features_in_ = X.shape[1]
        return self

    def transform(self, X: pl.DataFrame) -> pl.DataFrame:
        check_is_fitted(self)
        return X.drop([c for c in self.features_to_drop if c in X.columns])


class LowNonZeroFeatureRemover(TransformerMixin, BaseEstimator):
    def __init__(self, threshold: int = 200) -> None:
        self.threshold = threshold

    def fit(self, X: pl.DataFrame, y=None):
        self.n_features_in_ = X.shape[1]
        numeric_cols = X.select(cs.numeric()).columns
        self.features_to_drop_ = [col for col in numeric_cols if (X[col] != 0).sum() <= self.threshold]
        return self

    def transform(self, X: pl.DataFrame) -> pl.DataFrame:
        check_is_fitted(self, "features_to_drop_")
        return X.drop(self.features_to_drop_)


class DuplicatesRemover(TransformerMixin, BaseEstimator):
    def fit(self, X, y=None):
        self.n_features_in_ = X.shape[1]
        return self

    def transform(self, X) -> pl.DataFrame:
        return X.unique(keep="first", maintain_order=True)


class NullRemover(TransformerMixin, BaseEstimator):
    def fit(self, X, y=None):
        self.n_features_in_ = X.shape[1]
        return self

    def transform(self, X) -> pl.DataFrame:
        check_is_fitted(self)
        X = X.with_columns(pl.when(cs.numeric().is_infinite()).then(None).otherwise(cs.numeric()).name.keep())
        X = X.with_columns(cs.float().fill_nan(None).name.keep())
        return X.drop_nulls()


class ImpossibleNegativesRemover(TransformerMixin, BaseEstimator):
    def fit(self, X, y=None):
        self.n_features_in_ = X.shape[1]
        return self

    def transform(self, X) -> pl.DataFrame:
        check_is_fitted(self)
        return X.filter(~pl.any_horizontal(cs.numeric() < 0))


class GreedyCorrelationSelector(TransformerMixin, BaseEstimator):
    def __init__(self, threshold: float = 0.95) -> None:
        self.threshold = threshold

    def fit(self, X, y=None):
        self.n_features_in_ = X.shape[1]
        numeric_cols = X.select(cs.numeric()).columns
        corr_matrix = X.select(numeric_cols).corr().to_pandas()
        corr_matrix.index = numeric_cols

        self.features_to_drop_ = set()
        for i in range(len(corr_matrix.columns)):
            for j in range(i + 1, len(corr_matrix.columns)):
                col_a, col_b = corr_matrix.columns[i], corr_matrix.columns[j]
                if abs(corr_matrix.iloc[i, j]) > self.threshold and col_a not in self.features_to_drop_:
                    self.features_to_drop_.add(col_b)
        return self

    def transform(self, X) -> pl.DataFrame:
        check_is_fitted(self, "features_to_drop_")
        return X.drop(list(self.features_to_drop_))


class RelabelTarget(TransformerMixin, BaseEstimator):
    """Relabels '<attack> - Attempted' flows as BENIGN and optionally makes the label binary (attack = 1)."""

    def __init__(self, make_binary: bool = False) -> None:
        self.make_binary = make_binary

    def fit(self, X, y=None):
        self.n_features_in_ = X.shape[1]
        return self

    def transform(self, X) -> pl.DataFrame:
        X = X.with_columns(
            pl.when(pl.col("Label").str.ends_with("Attempted")).then(pl.lit("BENIGN"))
            .otherwise(pl.col("Label")).alias("Label")
        )
        if self.make_binary:
            X = X.with_columns(pl.when(pl.col("Label") == "BENIGN").then(0).otherwise(1).alias("Label"))
        return X


def clean_dataset(df: pl.DataFrame, identifier_features_to_drop: list[str] = IDENTIFIER_COLUMNS,
                  make_target_binary: bool = False, attack_only: bool = False) -> pl.DataFrame:
    cleaners = [
        IdentifierColumnsRemover(identifier_features_to_drop),
        NullRemover(),
        ImpossibleNegativesRemover(),
        RelabelTarget(make_target_binary),
        DuplicatesRemover(),
    ]
    for cleaner in cleaners:
        df = cleaner.fit_transform(df)
    if attack_only:
        df = df.filter(pl.col("Label") != "BENIGN")
    return df


def make_preprocessor() -> ColumnTransformer:
    return ColumnTransformer(
        transformers=[("protocol", OneHotEncoder(handle_unknown="ignore", sparse_output=False), ["Protocol"])],
        remainder="passthrough",
        verbose_feature_names_out=False,
    ).set_output(transform="pandas")


def to_float32(X):
    # the passthrough columns come out of the ColumnTransformer as object dtype when the input is a
    # polars frame; XGBoost rejects object columns, so cast everything back to numbers
    return X.astype("float32")


def make_model(model, low_non_zero_threshold: int = 200, correlation_threshold: float = 0.95):
    return make_pipeline(
        LowNonZeroFeatureRemover(low_non_zero_threshold),
        GreedyCorrelationSelector(correlation_threshold),
        make_preprocessor(),
        FunctionTransformer(to_float32),
        model,
    )
