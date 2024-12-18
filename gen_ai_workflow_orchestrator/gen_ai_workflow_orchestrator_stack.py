# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files(the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and / or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
import json
from aws_cdk import (
    Aws,
    CustomResource,
    Duration,
    RemovalPolicy,
    Stack,
    aws_athena as athena,
    aws_dynamodb as dynamodb,
    aws_healthlake as healthlake,
    aws_iam as iam,
    aws_kms as kms,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_s3 as s3,
    aws_stepfunctions as sfn,
    aws_ssm as ssm,
    custom_resources as cr,
)
from constructs import Construct
from cdk_nag import NagSuppressions


class GenAIWorkflowOrchestratorStack(Stack):
    """
    Creates the resources required for the Generative AI Workflow Orchestrator
    stack. See <blog post> URL for details.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        bedrock_models_for_access = []
        if self.node.try_get_context("use_inference_profile"):
            # When cross-region inference profile is used, we need to provide access to the models
            # in each region that it's available in
            for region in ["us-east-1", "us-east-2", "us-west-2"]:
                bedrock_models_for_access.append(self.node.try_get_context(
                    "bedrock_model_id").replace("<REGION>", region)
                )
            # Generate the Bedrock inference profile arn for the current region
            bedrock_inference_profile_arn = f"arn:aws:bedrock:{Aws.REGION}:{
                Aws.ACCOUNT_ID}:inference-profile/{self.node.try_get_context('bedrock_inference_profile_id')}"
            # Add the cross-region inference endpoint to IAM policy for access
            bedrock_models_for_access.append(bedrock_inference_profile_arn)
            # The endpoint which should be called from the state machine
            bedrock_model_endpoint = bedrock_inference_profile_arn
        else:
            # Otherwise, only use the model from the current region
            bedrock_model_endpoint = self.node.try_get_context("bedrock_model_id").replace(
                "<REGION>", Aws.REGION)
            bedrock_models_for_access.append(
                bedrock_model_endpoint
            )

        # create a KMS key for encrypting data in s3 buckets
        s3_kms_key = kms.Key(
            self,
            "S3KMSKey",
            alias=self.node.try_get_context("kms_alias_s3_key"),
            description="KMS key for encrypting data in S3 in GenAI Workflow Orchestrator demo",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # create a KMS key for encryption data in CloudWatch
        cw_key_policy = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=["kms:*"],
                    principals=[iam.AccountRootPrincipal()],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    actions=[
                        "kms:Encrypt*",
                        "kms:Decrypt*",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Describe*",
                    ],
                    principals=[iam.ServicePrincipal("logs.amazonaws.com")],
                    resources=["*"],
                    conditions={
                        "ArnEquals": {
                            "kms:EncryptionContext:aws:logs:arn": [
                                f'arn:aws:logs:{Aws.REGION}:{Aws.ACCOUNT_ID}:log-group:/aws/stepfunctions/{
                                    self.node.try_get_context("gen_ai_workflow_state_machine_name")}',
                            ]
                        }
                    },
                ),
            ]
        )
        cw_kms_key = kms.Key(
            self,
            "CWKMSKey",
            alias=self.node.try_get_context("kms_alias_cloudwatch_key"),
            description="KMS key for encrypting data in CloudWatch in GenAI Workflow Orchestrator demo",
            enable_key_rotation=True,
            policy=cw_key_policy,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Amazon S3 access log bucket
        s3_access_log_bucket = s3.Bucket(
            self,
            "S3AccessLogBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=s3_kms_key,
            enforce_ssl=True,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            auto_delete_objects=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Amazon S3 bucket used to store query results
        s3_athena_query_results_bucket = s3.Bucket(
            self,
            "AthenaQueryResultsBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=s3_kms_key,
            enforce_ssl=True,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            server_access_logs_bucket=s3_access_log_bucket,
            server_access_logs_prefix="athena-query-results",
            auto_delete_objects=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Amazon Athena Workgroup
        athena_workgroup = athena.CfnWorkGroup(
            self,
            "AthenaWorkgroup",
            name=self.node.try_get_context("athena_workgroup_name"),
            description="Amazon Athena Workgroup for GenAI workflow orchestrator",
            state="ENABLED",
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                publish_cloud_watch_metrics_enabled=True,
                bytes_scanned_cutoff_per_query=1099511627776000,
                customer_content_encryption_configuration=athena.CfnWorkGroup.CustomerContentEncryptionConfigurationProperty(
                    kms_key=s3_kms_key.key_arn
                ),
                enforce_work_group_configuration=True,
                engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                    selected_engine_version="AUTO"
                ),
                result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="SSE_KMS", kms_key=s3_kms_key.key_arn
                    ),
                    output_location=f"s3://{
                        s3_athena_query_results_bucket.bucket_name}/",
                ),
            ),
            recursive_delete_option=True,
        )

        # Sample AWS HealthLake Data Store with Synthea data
        healthlake_data_store_name = self.node.try_get_context(
            "healthlake_data_store_name"
        )
        healthlake_data_store = healthlake.CfnFHIRDatastore(
            self,
            "HealthLakeDataStore",
            datastore_type_version="R4",
            datastore_name=healthlake_data_store_name,
            preload_data_config=healthlake.CfnFHIRDatastore.PreloadDataConfigProperty(
                preload_data_type="SYNTHEA"
            ),
        )

        healthlake_database_name = f"{healthlake_data_store_name}_{
            healthlake_data_store.attr_datastore_id}_healthlake_view"

        # Lambda function to format the record
        format_record = lambda_.Function(
            self,
            "FormatRecord",
            runtime=lambda_.Runtime.PYTHON_3_13,
            code=lambda_.Code.from_asset("lambda/format_record"),
            handler="format_record.lambda_handler",
            timeout=Duration.seconds(60),
            function_name=self.node.try_get_context(
                "format_record_function_name"),
        )

        # Lambda function to process GenAI output
        process_gen_ai_output = lambda_.Function(
            self,
            "ProcessGenAIOutput",
            runtime=lambda_.Runtime.PYTHON_3_13,
            code=lambda_.Code.from_asset("lambda/process_gen_ai_output"),
            handler="process_gen_ai_output.lambda_handler",
            timeout=Duration.seconds(60),
            function_name=self.node.try_get_context(
                "process_gen_ai_output_function_name"
            ),
        )

        # DynamoDB table to store the generative AI results
        results_table = dynamodb.Table(
            self,
            "ResultsTable",
            partition_key=dynamodb.Attribute(
                name="RecordId", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="UpdatedTime", type=dynamodb.AttributeType.STRING
            ),
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            table_name=self.node.try_get_context("results_table_name"),
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.DESTROY,
        )
        results_table.auto_scale_read_capacity(min_capacity=1, max_capacity=5)
        results_table.auto_scale_write_capacity(min_capacity=1, max_capacity=5)

        # Create SSM parameter for the gen AI workflow state machine
        query_parameter_json = self.node.try_get_context("query_parameter")
        query_parameter_json["Database"] = healthlake_database_name
        query_parameter_parameter = ssm.StringParameter(
            self,
            "QuerySsmParameter",
            string_value=json.dumps(query_parameter_json, indent=2),
            parameter_name=self.node.try_get_context("query_parameter_name"),
            description=f'Initial parameters for the {self.node.try_get_context(
                "gen_ai_workflow_state_machine_name")} state machine',
        )

        # SSM Parameters for prompt template
        with open("model_prompts/prompt-template", "r", encoding="utf-8") as f:
            prompt_template = f.read()
            prompt_parameter = ssm.StringParameter(
                self,
                "Prompt",
                parameter_name=self.node.try_get_context(
                    "prompt_template_parameter_name"
                ),
                description="The prompt sent to the generative AI to perform a task",
                tier=ssm.ParameterTier.ADVANCED,
                string_value=prompt_template,
            )

        # State Machine IAM execution role
        state_machine_execution_role = iam.Role(
            self,
            "GenAIWorkflowExecutionRole",
            assumed_by=iam.ServicePrincipal("states.amazonaws.com"),
            description="Execution role for the GenAI workflow state machine",
        )

        # State Machine KMS key
        stepfunctions_kms_key = kms.Key(
            self,
            "StepFunctionsKMSKey",
            alias=self.node.try_get_context("kms_alias_stepfunctions_key"),
            description="KMS key for encrypting data in Step Functions in GenAI Workflow Orchestrator demo",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
        )
        stepfunctions_kms_key.add_to_resource_policy(
            statement=iam.PolicyStatement(
                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                principals=[iam.ArnPrincipal(
                    state_machine_execution_role.role_arn)],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "kms:EncryptionContext:aws:states:stateMachineArn": f'arn:aws:states:{Aws.REGION}:{Aws.ACCOUNT_ID}:stateMachine:{
                            self.node.try_get_context("gen_ai_workflow_state_machine_name")}'
                    }
                },
            )
        )

        # AWS Step Functions state machine
        sfn.StateMachine(
            self,
            "GenAIWorkflowStateMachine",
            definition_body=sfn.DefinitionBody.from_file(
                "state_machines/generative_ai_workflow.json"
            ),
            definition_substitutions={
                "QUERY_PARAMETER_NAME": self.node.try_get_context(
                    "query_parameter_name"
                ),
                "BEDROCK_MODEL_ID": bedrock_model_endpoint,
                "RESULTS_TABLE_NAME": self.node.try_get_context("results_table_name"),
                "FORMAT_RECORD_FUNCTION": format_record.function_arn,
                "PROCESS_GEN_AI_OUTPUT_FUNCTION": process_gen_ai_output.function_arn,
                "PROMPT_TEMPLATE_PARAMETER_NAME": self.node.try_get_context(
                    "prompt_template_parameter_name"
                ),
            },
            encryption_configuration=sfn.CustomerManagedEncryptionConfiguration(
                kms_key=stepfunctions_kms_key
            ),
            role=state_machine_execution_role,
            state_machine_name=self.node.try_get_context(
                "gen_ai_workflow_state_machine_name"
            ),
            logs=sfn.LogOptions(
                destination=logs.LogGroup(
                    self,
                    "GenAIWorkflowLogGroup",
                    log_group_name=f'/aws/stepfunctions/{
                        self.node.try_get_context("gen_ai_workflow_state_machine_name")}',
                    encryption_key=cw_kms_key,
                    removal_policy=RemovalPolicy.DESTROY,
                ),
                include_execution_data=True,
                level=sfn.LogLevel.ALL,
            ),
            tracing_enabled=True,
        )

        # IAM managed policy for use with AWS Step Functions state machines
        state_machine_iam_policy = iam.ManagedPolicy(
            self,
            "StateMachineIamPolicy",
            description="General IAM policy for use with AWS Step Functions state machines",
            document=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        sid="AthenaQueryPermission",
                        actions=[
                            "athena:StartQueryExecution",
                            "athena:GetQueryExecution",
                            "athena:GetQueryResults",
                            "s3:PutObject",
                            "s3:GetObject",
                            "s3:GetBucketLocation",
                        ],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f"arn:aws:athena:{Aws.REGION}:{
                                Aws.ACCOUNT_ID}:workgroup/{athena_workgroup.name}",
                            s3_athena_query_results_bucket.bucket_arn,
                            f"{s3_athena_query_results_bucket.bucket_arn}/*",
                        ],
                    ),
                    iam.PolicyStatement(
                        sid="GlueDatabaseAccessPermission",
                        actions=["glue:GetDatabase", "glue:GetDatabases"],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f"arn:aws:glue:{Aws.REGION}:{
                                Aws.ACCOUNT_ID}:catalog",
                            f"arn:aws:glue:{Aws.REGION}:{
                                Aws.ACCOUNT_ID}:database/*",
                        ],
                    ),
                    iam.PolicyStatement(
                        actions=["bedrock:InvokeModel"],
                        sid="BedrockModelAccess",
                        effect=iam.Effect.ALLOW,
                        resources=bedrock_models_for_access,
                    ),
                    iam.PolicyStatement(
                        actions=["lambda:InvokeFunction"],
                        sid="LambdaAccess",
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f"{process_gen_ai_output.function_arn}",
                            f"{format_record.function_arn}",
                        ],
                    ),
                    iam.PolicyStatement(
                        sid="GlueTableAccessPermissionForHealthLakeData",
                        actions=["glue:GetTable", "glue:GetTables"],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f"arn:aws:glue:{Aws.REGION}:*:*",
                        ],
                    ),
                    iam.PolicyStatement(
                        sid="LakeFormationDataAccessPermissionForHealthLakeData",
                        actions=["lakeformation:GetDataAccess"],
                        effect=iam.Effect.ALLOW,
                        resources=["*"],
                    ),
                    iam.PolicyStatement(
                        sid="ExecuteDistributedMap",
                        actions=["states:StartExecution"],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f'arn:aws:states:{Aws.REGION}:{Aws.ACCOUNT_ID}:stateMachine:{
                                self.node.try_get_context("gen_ai_workflow_state_machine_name")}'
                        ],
                    ),
                    iam.PolicyStatement(
                        sid="CloudWatchEventsAccess",
                        actions=[
                            "events:DescribeRule",
                            "events:PutRule",
                            "events:PutTargets",
                        ],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f"arn:aws:events:{Aws.REGION}:{
                                Aws.ACCOUNT_ID}:rule/StepFunctionsGetEventsForStepFunctionsExecutionRule"
                        ],
                    ),
                ]
            ),
        )

        # Add permissions to the GenAI workflow state machine IAM role
        query_parameter_parameter.grant_read(state_machine_execution_role)
        state_machine_execution_role.add_managed_policy(
            state_machine_iam_policy)
        prompt_parameter.grant_read(state_machine_execution_role)
        results_table.grant_read_write_data(state_machine_execution_role)
        s3_kms_key.grant_encrypt_decrypt(state_machine_execution_role)
        # Create LakeFormation resource link

        # Role to be used by Custom CloudFormation resource
        custom_resource_role = iam.Role(
            self,
            "CustomResourceExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                custom_resource_policy := iam.ManagedPolicy(
                    self,
                    "CustomResourcePolicy",
                    description="Accumulated permissions for the singleton Lambda function used by custom resources",
                    document=iam.PolicyDocument(
                        statements=[
                            iam.PolicyStatement(
                                actions=[
                                    "lakeformation:GrantPermissions",
                                    "lakeformation:RevokePermissions",
                                    "ram:GetResourceShares",
                                    "ram:ListResources",
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                    "glue:GetTables",
                                    "glue:GetDatabase",
                                ],
                                effect=iam.Effect.ALLOW,
                                resources=["*"],
                            ),
                        ]
                    )
                )
            ]
        )

        # Retrieve the ARN of the HealthLake database
        cr_healthlake_shared_database = cr.AwsCustomResource(
            self,
            "GetSharedDatabases",
            on_create=cr.AwsSdkCall(
                service="Ram",
                action="listResources",
                parameters={
                    "resourceType": "glue:Database",
                    "resourceOwner": "OTHER-ACCOUNTS",
                    "query": f"resources[? contains(arn, 'database/{healthlake_database_name}')]",
                },
                physical_resource_id=cr.PhysicalResourceId.from_response(
                    "resources.0.resourceShareArn"
                ),
            ),
            role=custom_resource_role,
        )

        cr_healthlake_shared_database.node.add_dependency(
            healthlake_data_store)

        cr_healthlake_shared_database_details = cr.AwsCustomResource(
            self,
            "GetResourceShares",
            on_create=cr.AwsSdkCall(
                service="Ram",
                action="getResourceShares",
                parameters={
                    "resourceOwner": "OTHER-ACCOUNTS",
                    "resourceShareArns": [
                        cr_healthlake_shared_database.get_response_field(
                            "resources.0.resourceShareArn"
                        )
                    ],
                },
                physical_resource_id=cr.PhysicalResourceId.from_response(
                    "resourceShares.0.name"
                ),
            ),
            role=custom_resource_role,
        )

        # AWS Lambda function to add custom resource role as the LakeFormation data lake admin
        # Code provided inline to avoid requiring Docker to build in cfnresponse dependency
        lambda_add_lf_data_lake_admin = lambda_.Function(
            self,
            "AddLakeFormationDataLakeAdmin",
            runtime=lambda_.Runtime.PYTHON_3_13,
            code=lambda_.Code.from_inline('''
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
# with the License. A copy of the License is located at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
import cfnresponse
import boto3
import os

lakeformation_client = boto3.client("lakeformation")
datalake_admin_role_arn = os.environ.get("DATA_LAKE_ADMIN_ROLE_ARN")


def lambda_handler(event, context):  # pylint: disable=unused-argument
    print(event)

    request_type = event.get("RequestType")

    try:
        datalake_settings = lakeformation_client.get_data_lake_settings()
        data_lake_admins = datalake_settings.get("DataLakeSettings").get(
            "DataLakeAdmins", []
        )
        print(f"current data lake admins: {data_lake_admins}")

        if request_type == "Create" or request_type == "Update":
            data_lake_admins.append(
                {"DataLakePrincipalIdentifier": datalake_admin_role_arn}
            )
            print(f"adding {datalake_admin_role_arn} to data lake admins")
            response = lakeformation_client.put_data_lake_settings(
                DataLakeSettings={"DataLakeAdmins": data_lake_admins}
            )
            print(response)

        if request_type == "Delete":
            new_data_lake_admins = [
                admin
                for admin in data_lake_admins
                if admin["DataLakePrincipalIdentifier"] != datalake_admin_role_arn
            ]
            if len(new_data_lake_admins) == len(data_lake_admins):
                print("No changes to data lake admins required")
            else:
                print(f"removing {datalake_admin_role_arn} from data lake admins")
                response = lakeformation_client.put_data_lake_settings(
                    DataLakeSettings={"DataLakeAdmins": new_data_lake_admins}
                )
                print(response)
    except Exception as err:
        print("Error when updating LakeFormation data lake settings", err)
        cfnresponse.send(
            event, context, cfnresponse.FAILED, {}, context.log_stream_name
        )

    cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, context.log_stream_name)
            '''),
            handler="index.lambda_handler",
            timeout=Duration.seconds(30),
            environment={
                "DATA_LAKE_ADMIN_ROLE_ARN": custom_resource_role.role_arn},
        )
        add_lf_datalake_admin_policy = iam.ManagedPolicy(
            self,
            "AddLakeFormationDataLakeAdminPolicy",
            description="Permissions used by the custom resource lambda function to update LakeFormation data lake admin",
            document=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=[
                            "lakeformation:PutDataLakeSettings",
                            "lakeformation:GetDataLakeSettings",
                        ],
                        effect=iam.Effect.ALLOW,
                        resources=["*"],
                    ),
                ]
            ),
        )
        lambda_add_lf_data_lake_admin.role.add_managed_policy(
            add_lf_datalake_admin_policy
        )

        # Custom resource to add role as a LakeFormation admin
        cr_add_lf_data_lake_admin = CustomResource(
            self,
            "AddLakeFormationDataLakeAdminCustomResource",
            service_token=lambda_add_lf_data_lake_admin.function_arn,
        )

        # Grants state machine execution role DESCRIBE access to database
        cr_grant_healthlake_database_permission = cr.AwsCustomResource(
            self,
            "GrantHealthLakeDatabasePermission",
            on_create=cr.AwsSdkCall(
                service="LakeFormation",
                action="grantPermissions",
                parameters={
                    "Permissions": ["DESCRIBE"],
                    "Principal": {
                        "DataLakePrincipalIdentifier": state_machine_execution_role.role_arn
                    },
                    "Resource": {
                        "Database": {
                            "CatalogId": Aws.ACCOUNT_ID,
                            "Name": healthlake_database_name,
                        }
                    },
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    "GrantHealthLakeDatabasePermission"
                ),
            ),
            on_delete=cr.AwsSdkCall(
                service="LakeFormation",
                action="revokePermissions",
                parameters={
                    "Permissions": ["DESCRIBE"],
                    "Principal": {
                        "DataLakePrincipalIdentifier": state_machine_execution_role.role_arn
                    },
                    "Resource": {
                        "Database": {
                            "CatalogId": Aws.ACCOUNT_ID,
                            "Name": healthlake_database_name,
                        }
                    },
                },
            ),
            role=custom_resource_role,
        )

        cr_grant_healthlake_database_permission.node.add_dependency(
            cr_add_lf_data_lake_admin
        )

        # Grants state machine execution role SELECT, DESCRIBE access to database and its tables
        cr_grant_healthlake_tables_permission = cr.AwsCustomResource(
            self,
            "GrantHealthLakeReadPermissionsToStateMachine",
            on_create=cr.AwsSdkCall(
                service="LakeFormation",
                action="grantPermissions",
                parameters={
                    "Permissions": ["SELECT", "DESCRIBE"],
                    "Principal": {
                        "DataLakePrincipalIdentifier": state_machine_execution_role.role_arn
                    },
                    "Resource": {
                        "Table": {
                            "CatalogId": cr_healthlake_shared_database_details.get_response_field(
                                "resourceShares.0.owningAccountId"
                            ),
                            "DatabaseName": healthlake_database_name,
                            "TableWildcard": {},
                        }
                    },
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    "GrantHealthLakeReadPermissionsToStateMachine"
                ),
            ),
            on_delete=cr.AwsSdkCall(
                service="LakeFormation",
                action="revokePermissions",
                parameters={
                    "Permissions": ["SELECT", "DESCRIBE"],
                    "Principal": {
                        "DataLakePrincipalIdentifier": state_machine_execution_role.role_arn
                    },
                    "Resource": {
                        "Table": {
                            "CatalogId": cr_healthlake_shared_database_details.get_response_field(
                                "resourceShares.0.owningAccountId"
                            ),
                            "DatabaseName": healthlake_database_name,
                            "TableWildcard": {},
                        }
                    },
                },
            ),
            role=custom_resource_role,
        )

        cr_grant_healthlake_tables_permission.node.add_dependency(
            cr_add_lf_data_lake_admin
        )

        # CDK NAG suppressions
        NagSuppressions.add_resource_suppressions(
            state_machine_execution_role,
            suppressions=[
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "A policy with wildcard statements is necessary for the successful "
                        "creation of the state machine"
                    ),
                },
                {
                    "id": "HIPAA.Security-IAMNoInlinePolicy",
                    "reason": (
                        "A policy with wildcard statements is necessary for the successful "
                        "creation of the state machine"
                    ),
                },
            ],
            apply_to_children=True,
        )

        NagSuppressions.add_resource_suppressions(
            results_table,
            suppressions=[
                {
                    "id": "HIPAA.Security-DynamoDBInBackupPlan",
                    "reason": "The DynamoDB table is not required to be backed up in this demo solution",
                }
            ],
        )

        NagSuppressions.add_resource_suppressions(
            [
                state_machine_iam_policy,
                custom_resource_policy,
                add_lf_datalake_admin_policy,
            ],
            suppressions=[
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "Using wildcard in policy statement to allow actions required for "
                        "customer managed policies"
                    ),
                }
            ],
            apply_to_children=True
        )

        NagSuppressions.add_resource_suppressions(
            format_record,
            suppressions=[
                {
                    "id": "HIPAA.Security-IAMNoInlinePolicy",
                    "reason": (
                        "Inline policy for Lambda function is created by CDK to allow the Lambda "
                        "function to use DLQ"
                    ),
                }
            ],
            apply_to_children=True,
        )

        NagSuppressions.add_resource_suppressions(
            process_gen_ai_output,
            suppressions=[
                {
                    "id": "HIPAA.Security-IAMNoInlinePolicy",
                    "reason": (
                        "Inline policy for Lambda function is created by CDK to allow the Lambda "
                        "function to use DLQ"
                    ),
                }
            ],
            apply_to_children=True,
        )

        NagSuppressions.add_stack_suppressions(
            self,
            [
                {
                    "id": "AwsSolutions-L1",
                    "reason": "Latest runtime version not required for this application",
                },
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "Lambda execution policy for custom resources created by CDK",
                    "appliesTo": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                    ],
                },
                {
                    "id": "HIPAA.Security-S3BucketReplicationEnabled",
                    "reason": "bucket data replication is not needed for this solution",
                },
                {
                    "id": "HIPAA.Security-LambdaInsideVPC",
                    "reason": (
                        "In this demo solution, the lambda function is neither invoked within a VPC, or calling "
                        "any external services, therefore no VPC attachment is required"
                    ),
                },
                {
                    "id": "HIPAA.Security-LambdaDLQ",
                    "reason": "Lambda functions used in this solution are synchronous, DQL is not needed",
                },
                {
                    "id": "HIPAA.Security-LambdaConcurrency",
                    "reason": "Not reserving Lambda concurrency in this solution",
                },
            ],
        )
