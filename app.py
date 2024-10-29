#!/usr/bin/env python3
import os

import aws_cdk as cdk
from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks
from cdk_nag import HIPAASecurityChecks

from gen_ai_workflow_orchestrator.gen_ai_workflow_orchestrator_stack import GenAIWorkflowOrchestratorStack

SUPPORTED_REGIONS = ['us-east-1', 'us-west-2']
if os.getenv('CDK_REGION') not in SUPPORTED_REGIONS:
    raise ValueError(
        f"Unsupported AWS region: {os.getenv('CDK_REGION')}. "
        'Based on current Bedrock Model availability, the supported regions '
        f"for this solution are: {', '.join(SUPPORTED_REGIONS)}")
app = cdk.App()
stack = GenAIWorkflowOrchestratorStack(
    app,
    'GenAIWorkflowOrchestratorStack',
    description='Resources for the Generative AI Workflow Orchestrator',
    env=cdk.Environment(
        account=os.getenv('CDK_ACCOUNT'),
        region=os.getenv('CDK_REGION')
    )
)

cdk.Tags.of(stack).add(stack.node.try_get_context('project_tag_key'),
                       stack.node.try_get_context('project_tag_value'))
cdk.Tags.of(stack).add(stack.node.try_get_context(
    'environment_tag_key'), stack.node.try_get_context('environment_tag_value'))
Aspects.of(app).add(AwsSolutionsChecks())
Aspects.of(app).add(HIPAASecurityChecks())
app.synth()
