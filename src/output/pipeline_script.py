from autoai_libs.transformers.exportable import ColumnSelector
from autoai_libs.transformers.exportable import NumpyColumnSelector
from autoai_libs.transformers.exportable import FloatStr2Float
from autoai_libs.transformers.exportable import NumpyReplaceMissingValues
from autoai_libs.transformers.exportable import NumImputer
from autoai_libs.transformers.exportable import OptStandardScaler
from autoai_libs.transformers.exportable import float32_transform
from xgboost import XGBClassifier
import lale

lale.wrap_imported_operators(["autoai_libs.transformers.exportable"])
column_selector = ColumnSelector(
    columns_indices_list=[0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
)
numpy_column_selector = NumpyColumnSelector(
    columns=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
)
float_str2_float = FloatStr2Float(
    dtypes_list=[
        "float_num", "float_int_num", "float_int_num", "float_num",
        "float_num", "float_int_num", "float_int_num", "float_num",
        "float_num", "float_num", "float_int_num", "float_int_num",
    ],
    missing_values_reference_list=[],
)
numpy_replace_missing_values = NumpyReplaceMissingValues(
    missing_values=[], filling_values=float("nan")
)
num_imputer = NumImputer(strategy="median", missing_values=float("nan"))
opt_standard_scaler = OptStandardScaler(use_scaler_flag=False)
xgb_classifier = XGBClassifier(
    max_depth=3,
    min_child_weight=1,
    missing=float("nan"),
    n_estimators=100,
    random_state=33,
    tree_method="hist",
    verbosity=0,
    silent=True,
)
pipeline = (
    column_selector
    >> numpy_column_selector
    >> float_str2_float
    >> numpy_replace_missing_values
    >> num_imputer
    >> opt_standard_scaler
    >> float32_transform()
    >> xgb_classifier
)