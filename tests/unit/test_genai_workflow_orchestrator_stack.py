import aws_cdk as core
import aws_cdk.assertions as assertions

from gen_ai_workflow_orchestrator.gen_ai_workflow_orchestrator_stack import GenAIWorkflowOrchestratorStack

# example tests. To run these tests, uncomment this file along with the example
# resource in gen_ai_workflow_orchestrator_stack/gen_ai_workflow_orchestrator_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = GenAIWorkflowOrchestratorStack(app, "gen-ai-workflow-orchestrator")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
