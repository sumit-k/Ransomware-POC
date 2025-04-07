#!/usr/bin/env python3

import os
import time
import argparse
import json
import sys
from datetime import datetime # For timestamped names
from dotenv import load_dotenv
import json
import pandas as pd


# --- Try importing WML SDK ---
try:
    from ibm_watsonx_ai import APIClient
    from ibm_watsonx_ai.experiment import AutoAI
    from ibm_watsonx_ai.helpers import pipeline_to_script
    from ibm_watsonx_ai.utils.autoai.enums import BatchedClassificationAlgorithms
    # Use V4_datadefinitions for defining data source schema if needed,
    # but DataConnection usually sufficient for AutoAI with CSV.
    from ibm_watsonx_ai.helpers.connections import DataConnection, S3Connection, S3Location
    WML_SDK_AVAILABLE = True
except ImportError:
    WML_SDK_AVAILABLE = False

# --- Argument Parsing ---
def parse_args():
    parser = argparse.ArgumentParser(
        description="Run IBM Watson AutoAI (Periodic Retraining Strategy) on data from IBM COS, defaulting to Classification.",
        epilog="This script initiates a NEW AutoAI experiment run on the specified dataset. "
               "For incremental updates, manage data accumulation in COS and run this script periodically."
    )

    # --- WML Connection ---
    wml_group = parser.add_argument_group('IBM Watson Machine Learning Configuration')
    wml_group.add_argument('--apikey', default=os.environ.get('IBMCLOUD_API_KEY'),
                           help='IBM Cloud API Key (or set IBMCLOUD_API_KEY env var)')
    wml_group.add_argument('--wml_url', default=os.environ.get('WML_ENDPOINT'),
                           help='IBM WML Service Endpoint URL (or set WML_ENDPOINT env var)')
    wml_group.add_argument('--space_id', default=os.environ.get('WML_SPACE_ID'),
                           help='IBM WML Deployment Space ID (or set WML_SPACE_ID env var)')
    wml_group.add_argument('--project_id', default=os.environ.get('WML_PROJECT_ID'),
                           help='IBM WML Project ID (alternative to space_id, or set WML_PROJECT_ID env var)')

    # --- COS Data Source ---
    cos_group = parser.add_argument_group('IBM Cloud Object Storage Data Source')
    cos_group.add_argument('--cos_endpoint', default=os.environ.get('IBM_COS_ENDPOINT_URL'),
                           help='IBM COS Endpoint URL (or set IBM_COS_ENDPOINT_URL env var)')
    cos_group.add_argument('--cos_bucket', default=os.environ.get('IBM_COS_BUCKET_NAME'),
                           help='IBM COS Bucket Name containing the data file (or set IBM_COS_BUCKET_NAME env var)')
    cos_group.add_argument('--cos_file', required=True,
                           help='Filename (Object Key) of the UPDATED CSV data file within the COS bucket for THIS run.')
    cos_group.add_argument('--cos_access_key', default=os.environ.get('IBM_COS_ACCESS_KEY_ID'),
                           help='IBM COS Access Key ID (or set IBM_COS_ACCESS_KEY_ID env var)')
    cos_group.add_argument('--cos_secret_key', default=os.environ.get('IBM_COS_SECRET_ACCESS_KEY'),
                           help='IBM COS Secret Access Key (or set IBM_COS_SECRET_ACCESS_KEY env var)')

    # --- AutoAI Experiment ---
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_exp_name = f"ebpf-metrics-classification-autoai-{now_str}"

    autoai_group = parser.add_argument_group('AutoAI Experiment Configuration')
    autoai_group.add_argument('--experiment_name', default=default_exp_name,
                              help=f'Name for THIS AutoAI experiment run (default: {default_exp_name}).')
    # --- DEFAULTS SET FOR CLASSIFICATION ---
    autoai_group.add_argument('--prediction_type',
                              default=AutoAI.PredictionType.BINARY, # Default is multiclass
                              #choices=[ptype.value for ptype in AutoAI.PredictionType],
                              help='Type of prediction task. "binary" or "multiclass" (default: multiclass).')
    autoai_group.add_argument('--target_column',
                              default='label', # Default target is 'label'
                              help='Name of the column in the CSV file to predict (default: label). Ensure this column exists in your CSV.')
    # --- Other AutoAI Options ---
    autoai_group.add_argument('--desc', default='AutoAI classification on EBPF block metrics from COS.',
                               help='Description for the AutoAI experiment.')
    autoai_group.add_argument('--max_pipelines', type=int, default=4,
                               help='Maximum number of candidate pipelines AutoAI should generate.')
    autoai_group.add_argument('--positive_label', default=None,
                               help='Positive class label (required ONLY if --prediction_type is "binary").')
    autoai_group.add_argument('--test_size', type=float, default=0.15,
                               help='Fraction of data to use for the holdout/test set.')

    args = parser.parse_args()

    # --- Validation ---
    if not WML_SDK_AVAILABLE:
         parser.error("ibm-watson-machine-learning library not found. Please install it (`pip install ibm-watson-machine-learning`)")
    if not args.apikey or not args.wml_url:
        parser.error("Missing required WML credentials: --apikey and --wml_url (or env vars).")
    if not args.space_id and not args.project_id:
         parser.error("Missing WML context: --space_id or --project_id is required (or env vars).")
    if args.space_id and args.project_id:
         print("Warning: Both --space_id and --project_id provided. Using --space_id.")
         args.project_id = None
    if not args.cos_endpoint or not args.cos_bucket or not args.cos_access_key or not args.cos_secret_key:
         parser.error("Missing required COS credentials/info (--cos_endpoint, --cos_bucket, --cos_access_key, --cos_secret_key or env vars).")

    try:
        #pred_type_enum = AutoAI.PredictionType(args.prediction_type)
        pred_type_enum = AutoAI.PredictionType.BINARY
        if pred_type_enum == AutoAI.PredictionType.BINARY and not args.positive_label:
            parser.error("--positive_label is required when --prediction_type is 'binary'.")
    except ValueError:
         parser.error(f"Invalid --prediction_type: {args.prediction_type}")

    return args

# --- Main Function ---
def main():
    args = parse_args()

    # --- 1. Connect to IBM Watson Machine Learning ---
    wml_credentials = {"apikey": args.apikey, "url": args.wml_url}
    print("Connecting to IBM Watson Machine Learning...")
    try:
        client = APIClient(wml_credentials)
    except Exception as e: print(f"Error connecting to WML: {e}"); sys.exit(1)


    #client.spaces().list(limit=100)

    # --- Set Default Project/Space ---
    try:
        if args.space_id:
            print(f"Setting default WML Deployment Space ID: {args.space_id}")
            client.set.default_space(args.space_id)
        elif args.project_id:
             print(f"Setting default WML Project ID: {args.project_id}")
             client.set.default_project(args.project_id)
        else: print("Error: No WML Space ID or Project ID specified."); sys.exit(1)
        print("WML client configured successfully.")
    except Exception as e: print(f"Error setting default space/project: {e}"); sys.exit(1)

    # --- 2. Define Data Connection to IBM COS ---
    print(f"Defining data connection to IBM COS file: s3://{args.cos_bucket}/{args.cos_file}")
    '''
    data_conn = DataConnection(
        connection=S3Connection(
            endpoint_url=args.cos_endpoint,
            access_key_id=args.cos_access_key,
            secret_access_key=args.cos_secret_key
        ),
        location=S3Location(
            bucket=args.cos_bucket,
            path=args.cos_file
        )
    )

    connection_details = client.connections.create({
       client.connections.ConfigurationMetaNames.NAME: "Connection to COS",
       client.connections.ConfigurationMetaNames.DATASOURCE_TYPE: client.connections.get_datasource_type_id_by_name('bluemixcloudobjectstorage'),
       client.connections.ConfigurationMetaNames.PROPERTIES: {
        'bucket': args.cos_bucket,
        'access_key': args.cos_access_key,
        'secret_key': args.cos_secret_key,
        'iam_url': "https://iam.cloud.ibm.com/identity/token",
        'url': args.cos_endpoint
      }
    })
    '''

    connection_details = client.connections.create({
            'datasource_type': client.connections.get_datasource_type_uid_by_name('bluemixcloudobjectstorage'),
            'name': 'Connection to COS for tests',
            'properties': {
                'bucket': args.cos_bucket,
                'access_key': args.cos_access_key,
                'secret_key': args.cos_secret_key,
                'iam_url': "https://iam.cloud.ibm.com/identity/token",
                'url': args.cos_endpoint
            }
    })

    connection_id = client.connections.get_uid(connection_details)


    data_conn = DataConnection(
       connection_asset_id=connection_id,
       location=S3Location(
          bucket=args.cos_bucket,   # note: COS bucket name where training dataset is located
          path=args.cos_file  # note: path within bucket where your training dataset is located
        )
    )

    print(dir(data_conn))


    print(dir(AutoAI))
    # --- 3. Configure AutoAI Experiment ---
    print("Configuring AutoAI experiment...")
    try:
        '''
        prediction_type_enum = AutoAI.PredictionType(args.prediction_type)

        # Default scoring metric selection based on prediction type
        if prediction_type_enum in [AutoAI.PredictionType.BINARY, AutoAI.PredictionType.MULTICLASS]:
             scoring_metric = AutoAI.Metrics.ACCURACY_SCORE # Default for classification
        elif prediction_type_enum == AutoAI.PredictionType.REGRESSION:
             scoring_metric = AutoAI.Metrics.ROOT_MEAN_SQUARED_ERROR
        else:
             scoring_metric = None
             print(f"Warning: Unsupported prediction type '{prediction_type_enum}' for default metric selection.", file=sys.stderr)
        '''

        prediction_type_enum = AutoAI.PredictionType.MULTICLASS
        scoring_metric = AutoAI.Metrics.ACCURACY_SCORE

        '''

        auto_ai_optimizer = AutoAI(
            name=args.experiment_name,
            desc=args.desc,
            prediction_type=prediction_type_enum,
            prediction_column=args.target_column, # Defaults to 'label'
            scoring=scoring_metric, # Defaults based on type
            max_number_of_estimators=args.max_pipelines,
            test_size=args.test_size,
            positive_label=args.positive_label,
        )
        '''


        experiment = AutoAI(wml_credentials, space_id=args.space_id)

        pipeline_optimizer = experiment.optimizer(
           name=args.experiment_name,
           desc=args.desc,
           #t_shirt_size="l",
           prediction_type=prediction_type_enum,
           prediction_column=args.target_column,
           scoring=scoring_metric,
           #scoring=AutoAI.Metrics.ROC_AUC_SCORE,
           max_number_of_estimators=10,
           sample_size_limit=100,
           sampling_type="first_n_records",
           #retrain_on_holdout=True,
           daub_include_only_estimators=[AutoAI.ClassificationAlgorithms.XGB],
           include_only_estimators=[AutoAI.ClassificationAlgorithms.XGB],
           include_batched_ensemble_estimators=[BatchedClassificationAlgorithms.XGB],
           incremental_learning=True,
           holdout_size=args.test_size,
           #use_flight=True
        )

        print("calling get_params")
        print(pipeline_optimizer.get_params())
        #parsed = json.loads(pipeline_optimizer.get_params())
        #print(json.dumps(parsed, indent=4))
        print("get_params End")


        print(f"  Experiment Name: {args.experiment_name}")
        print(f"  Prediction Type: {args.prediction_type}")
        print(f"  Target Column: {args.target_column}")
        #print(f"  Optimizing Metric: {scoring_metric.value if scoring_metric else 'Auto'}")
        print(f"  Max Pipelines: {args.max_pipelines}")
        print(f"  Test Size: {args.test_size}")
        if prediction_type_enum == AutoAI.PredictionType.BINARY:
             print(f"  Positive Label: {args.positive_label}")

    except Exception as e: print(f"Error configuring AutoAI optimizer: {e}"); sys.exit(1)

    # --- 4. Run AutoAI Experiment ---
    print("\nStarting AutoAI experiment run (batch training on provided data)...")
    try:
        '''
        run_details = client.auto_ai.runs.create(
            auto_ai_optimizer,
            data_connection=[data_conn],
            background_mode=True
        )
        if not run_details: print("Error: Failed to start AutoAI run."); sys.exit(1)
        run_id = run_details['metadata']['id']
        print(f"AutoAI Run successfully submitted. Run ID: {run_id}")
        print("Monitoring run status (poll interval: 60 seconds)...")
        '''

        training_data_reference=[data_conn]
        print(dir(training_data_reference))

        run_details = pipeline_optimizer.fit(
            training_data_reference=training_data_reference,
            background_mode=False)

        if not run_details: 
            print("Error: Failed to start AutoAI run."); 
            sys.exit(1)

        run_id = run_details['metadata']['id']
        status = pipeline_optimizer.get_run_status()

    except Exception as e: print(f"Error submitting AutoAI run: {e}"); sys.exit(1)

    # --- 5. Monitor Run Status ---
    status = None
    while status not in ['completed', 'failed', 'canceled']:
        try:
            time.sleep(60)
            '''
            run_status_details = client.auto_ai.runs.get_details(run_id)
            status = run_status_details['metadata']['status']['state']
            '''
            status = pipeline_optimizer.get_run_status()
            print(f"  [{time.strftime('%H:%M:%S')}] Run Status: {status}")
        except KeyboardInterrupt: print("\nMonitoring interrupted."); sys.exit(0)
        except Exception as e: print(f"Error getting run status: {e}"); time.sleep(60)

    print(f"\nAutoAI Run finished with status: {status}")

    # --- 6. Get and Display Results ---
    if status == 'completed':
        print("\nFetching final run details and pipeline summary...")
        try:
            run_summary = pipeline_optimizer.summary()

            print("run_summary START  :  =>", run_summary)
            print("run_summary END")

            #pd.options.plotting.backend = "plotly"
            #run_summary.holdout_roc_auc.plot()

            print("Calling best_pipeline get")
            best_pipeline = pipeline_optimizer.get_pipeline(astype=AutoAI.PipelineTypes.SKLEARN)
            #best_pipeline = pipeline_optimizer.get_pipeline()
            print("Calling pipeline_to_script:", best_pipeline)
            print("calling steps::", best_pipeline.steps)
            pipeline_to_script(best_pipeline)

            #best_pipeline.visualize()

            #print("Calling best_pipeline.pretty_print")
            #best_pipeline.pretty_print(ipython_display=True, astype='sklearn')
            #print("Calling best_pipeline.pretty_print lale")
            #best_pipeline.pretty_print(ipython_display=True, astype='lale')

            print("Calling prediction")
            train_df = pipeline_optimizer.get_data_connections()[0].read()
            train_X = train_df.drop(['label'], axis=1).values
            train_y = train_df['label'].values

            predicted_y = best_pipeline.predict(train_X)
            predicted_y[:5]
        
            print("Calling runsummary")
            pipelines = run_summary.get('entity', {}).get('results', {}).get('summary', {}).get('leaderboard', [])
            if pipelines:
                 print("\n--- Pipeline Leaderboard ---")
                 # Display classification metrics
                 print(f"{'Pipeline Name':<15} {'Algorithm':<20} {'Holdout Accuracy':<20} {'Holdout AUC':<15}")
                 print("-" * 70)
                 for p in pipelines:
                      metrics = p.get('metrics', {})
                      acc = metrics.get('accuracy', {}).get('value', 'N/A')
                      auc = metrics.get('roc_auc', {}).get('value', 'N/A')
                      acc_str = f"{acc:.4f}" if isinstance(acc, (int, float)) else str(acc)
                      auc_str = f"{auc:.4f}" if isinstance(auc, (int, float)) else str(auc)
                      print(f"{p.get('name', 'N/A'):<15} {p.get('algorithm', 'N/A'):<20} {acc_str:<20} {auc_str:<15}")
                 print("-" * 70)
                 best_pipeline_name = pipelines[0].get('name')
                 print(f"\nBest pipeline found in this run: {best_pipeline_name}")
                 print("To use this model, you would typically store it as a WML asset and deploy it.")

            else: print("\nNo pipeline information found in the run summary.")
        except Exception as e: print(f"Error fetching/parsing run results: {e}")

    elif status == 'failed':
        print("\nAutoAI Run Failed.")
        '''
        try:
             run_failure_details = client.auto_ai.runs.get_details(run_id)
             failure_message = run_failure_details.get('metadata', {}).get('status', {}).get('message', 'No error message available.')
             print(f"Failure Reason: {failure_message}")
        except Exception as e: print(f"Could not fetch failure details: {e}")
        '''

    else: # Canceled
        print("\nAutoAI Run Canceled.")

    print(f"\nRun ID for reference: {run_id}")

# --- Run Main ---
if __name__ == "__main__":
    if not WML_SDK_AVAILABLE:
         print("Error: ibm-watson-machine-learning library not found.", file=sys.stderr)
         print("Please install it using: pip install ibm-watson-machine-learning", file=sys.stderr)
         sys.exit(1)
    load_dotenv("/home/sumit/code/expr/export")
    main()
