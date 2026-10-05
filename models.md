1. Compare RF, SVM, and XGBoost individually
All three were implemented in:
```
/srv/acquisition/analysis/run_baseline_ml.py
```

A. Inspect the model implementation
```
cd /srv/acquisition/analysis
grep -n -A20 -B5 "RandomForestClassifier" run_baseline_ml.py
```

For SVM:
```
grep -n -A15 -B5 "LinearSVC" run_baseline_ml.py
```

For XGBoost:
```
grep -n -A25 -B5 "XGBClassifier" run_baseline_ml.py
```

This gives you the exact implementation used rather than reconstructing it from memory.
2. Compare their validation performance
The complete baseline results are already stored in:
```
/srv/acquisition/analysis/results/baseline_ml/validation_results.csv
```

View the complete table:
```
column -s, -t < /srv/acquisition/analysis/results/baseline_ml/validation_results.csv | less -S

Or:
cat /srv/acquisition/analysis/results/baseline_ml/validation_results.csv
```

Compare only Random Forest
```
grep "random_forest" \
/srv/acquisition/analysis/results/baseline_ml/validation_results.csv
```

Compare only SVM
```
grep ",svm," \
/srv/acquisition/analysis/results/baseline_ml/validation_results.csv
```

Compare only XGBoost
```
grep "xgboost" \
/srv/acquisition/analysis/results/baseline_ml/validation_results.csv
```

This lets you document the performance of each model independently across the representations.

3. Compare the three models on the same representation

For a direct apples-to-apples comparison, use PE first.
```
grep -E "pe,(random_forest|svm|xgboost)," \
/srv/acquisition/analysis/results/baseline_ml/validation_results.csv
```

Then PE + DLL:
```
grep -E "pe_dll,(random_forest|svm|xgboost)," \
/srv/acquisition/analysis/results/baseline_ml/validation_results.csv
```

PE + API:
```
grep -E "pe_api,(random_forest|svm|xgboost)," \
/srv/acquisition/analysis/results/baseline_ml/validation_results.csv
```

PE + DLL + API:
```
grep -E "pe_dll_api,(random_forest|svm|xgboost)," \
/srv/acquisition/analysis/results/baseline_ml/validation_results.csv
```

This is the more scientifically meaningful comparison because the input representation is held constant.

4. Get the best configuration of each model

Random Forest
The tuning code is:
```
/srv/acquisition/analysis/run_rf_tuning.py
```

Inspect it:
```
less /srv/acquisition/analysis/run_rf_tuning.py
```

Results:
```
column -s, -t < \
/srv/acquisition/analysis/results/tuning/random_forest/rf_tuning_results.csv | less -S
```

Configuration:
```
cat \
/srv/acquisition/analysis/results/tuning/random_forest/rf_tuning_config.json
```

XGBoost
```
Code:
/srv/acquisition/analysis/run_xgb_tuning.py
```

View:
```
less /srv/acquisition/analysis/run_xgb_tuning.py
```

Results:
```
column -s, -t < \
/srv/acquisition/analysis/results/tuning/xgboost/xgb_tuning_results.csv | less -S
```

Configuration:
```
cat \
/srv/acquisition/analysis/results/tuning/xgboost/xgb_tuning_config.json
```

SVM
SVM did not have a separate tuning stage like RF and XGBoost. Its baseline implementation is in:
```
/srv/acquisition/analysis/run_baseline_ml.py
```

The model was:
LinearSVC(    C=1.0,    random_state=42,    max_iter=100000)


So for documentation, don't imply that SVM underwent the same hyperparameter tuning process.

5. Get the actual trained model code/configuration
For each trained baseline model, you have a directory such as:
results/baseline_ml/

List everything:
```
find /srv/acquisition/analysis/results/baseline_ml \
-type f | sort
```

For example:
```
find /srv/acquisition/analysis/results/baseline_ml \
-type f -name "model.joblib" | sort
```

The important point is that:
```
model.joblib
```

contains the serialized trained model, whereas:
```
run_baseline_ml.py
```

contains the source code used to construct/train it.
For project documentation, you should preserve both.

6. Get the code for every ML/DL model we have worked on
I'd document them in this structure.
Classical ML

Model	Source code
```
Random Forest	run_baseline_ml.py
Linear SVM	run_baseline_ml.py
XGBoost	run_baseline_ml.py
Random Forest tuning	run_rf_tuning.py
XGBoost tuning	run_xgb_tuning.py
Final RF test	run_final_test.py
```


Commands:
```
cd /srv/acquisition/analysis

sed -n '1,260p' run_baseline_ml.py

sed -n '1,300p' run_rf_tuning.py

sed -n '1,300p' run_xgb_tuning.py

sed -n '1,300p' run_final_test.py
```

If you want to save the exact source into documentation files:
```
cp run_baseline_ml.py documentation_run_baseline_ml.py
cp run_rf_tuning.py documentation_run_rf_tuning.py
cp run_xgb_tuning.py documentation_run_xgb_tuning.py
cp run_final_test.py documentation_run_final_test.py
```

I would not do that inside the canonical analysis directory unless you actually want duplicate files. For documentation, simply copying the source into a separate documentation directory is cleaner.

7. Static MLP code
We have three original static MLP experiments plus the architecture-selection experiment.
MLP + PE
```
less /srv/acquisition/analysis/run_mlp_static.py
```

MLP + PE + DLL
```
less /srv/acquisition/analysis/run_mlp_pe_dll.py
```

MLP + PE + API
```
less /srv/acquisition/analysis/run_mlp_pe_api.py
```

MLP architecture/regularization experiment
```
less /srv/acquisition/analysis/run_mlp_pe_dll_architecture.py
```

This last one is particularly important because Variant D was selected from this experiment.
8. Feature-engineering code
Since the models depend on the preprocessing pipeline, I strongly recommend documenting these as well.

PE feature construction
```
less /srv/acquisition/analysis/build_pe_features.py
```

TF-IDF DLL/API
```
less /srv/acquisition/analysis/build_tfidf_features.py
```

Combined representations
```
less /srv/acquisition/analysis/build_combined_features.py
```

Static PE extraction
```
less /srv/acquisition/analysis/extract_pe_features.py
```

Full extraction pipeline
```
less /srv/acquisition/analysis/run_full_static_extraction.py
```

9. One command to get the complete model/source inventory
Run:
```
cd /srv/acquisition/analysis
```
```
printf "\n===== CLASSICAL ML =====\n"
ls -lh run_baseline_ml.py run_rf_tuning.py run_xgb_tuning.py run_final_test.py
```
```
printf "\n===== STATIC DEEP LEARNING =====\n"
ls -lh run_mlp_static.py \
       run_mlp_pe_dll.py \
       run_mlp_pe_api.py \
       run_mlp_pe_dll_architecture.py

printf "\n===== FEATURE ENGINEERING =====\n"
ls -lh extract_pe_features.py \
       run_full_static_extraction.py \
       build_pe_features.py \
       build_tfidf_features.py \
       build_combined_features.py
```

That gives you a clean inventory for the documentation.

10. Most useful documentation comparison
For the actual report, I would make the comparison like this:
Model	Representation	Validation Accuracy	Validation Macro-F1	Final Test?
Random Forest	PE	83.13%	81.49%	Yes — 83.13% / 82.15% Macro-F1
XGBoost	PE	80.25%*	80.11%*	No
SVM	PE	60.49%	54.70%	No
MLP Variant D	PE + DLL	75.31%	73.30%	Pending


*The XGBoost figures here refer to the tuned validation configuration; the original baseline PE XGBoost was lower. For the final documentation, use the exact values from xgb_tuning_results.csv rather than manually transcribing them.
